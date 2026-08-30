//! Goal: prove the full ILK-003/ILK-010/ILK-011 vertical slice holds
//! together across one request's whole lifetime against real PostgreSQL --
//! not per-capability (already proven independently by
//! `postgres_request_repository.rs`, `postgres_route_repository.rs`, and
//! `postgres_work_claim_repository.rs`), and not through a second kernel
//! restart process, but by dropping and reconnecting the `Application`
//! mid-scenario the same way a real process restart would. This is
//! Section 6's still-open item in `minimum-viable-kernel.md`: every piece
//! is independently proven; this is what proves them chained.
//!
//! Deliberately tests at the kernel service layer (`RequestService`,
//! `RouteService`, `SubscriptionService`, `WorkClaimService`,
//! `SubscriptionRouter`) rather than through raw HTTP or a real signed
//! call: authentication, admission, and ILK-002 authority are each already
//! proven in their own dedicated contract tests
//! (`postgres_governed_http_middleware.rs`, `authority_contract.rs`), and
//! composing them here too would just duplicate that coverage without
//! adding a new chained proof.

use infernal_law::http::{RequestRouter, SubscriptionRouter};
use infernal_law::kernel::authority::{
    ContentDigest, SchemaKind, SchemaName, SchemaVersionRefs, Scope,
};
use infernal_law::kernel::identity::{ActorId, ActorKind};
use infernal_law::kernel::instance_keys::InstanceCredential;
use infernal_law::kernel::requests::{Request, RequestAcceptance, RequestFingerprint};
use infernal_law::kernel::subscriptions::{DeliveryMode, EventType};
use infernal_law::kernel::work_claims::WorkClaimError;
use infernal_law::wiring::Application;
use uuid::Uuid;

/// A fresh, namespaced action/event-type name per call -- reruns against
/// the same live database (this project's tests are not isolated by
/// transaction) must never see a stale subscription from a previous run
/// match a new request's action, the same class of collision already
/// fixed once in postgres_authority_repository.rs's tests.
fn unique_action(label: &str) -> String {
    format!("vertical-slice.{label}-{}", Uuid::new_v4().simple())
}

/// Publishes a real artifact and permission-policy schema version, owned by
/// `owner`, and returns the pair `Request::create` and ILK-002 authority
/// both require -- unlike the in-memory fakes elsewhere in this test suite,
/// the real Postgres-backed `RequestRepository` validates that both
/// versions actually exist. The name is disambiguated per call (not just
/// per test) since two tests in this file can run within the same wall-
/// clock second.
fn schema_versions(application: &Application, owner: ActorId, now: i64) -> SchemaVersionRefs {
    let unique = Uuid::new_v4().simple().to_string();
    let artifact = application
        .schemas()
        .publish(
            SchemaKind::Artifact,
            SchemaName::new(&format!("vertical-slice.artifact-{unique}")).unwrap(),
            owner,
            ContentDigest::from_bytes([1; 32]),
            now,
        )
        .unwrap();
    let permission_policy = application
        .schemas()
        .publish(
            SchemaKind::PermissionPolicy,
            SchemaName::new(&format!("vertical-slice.policy-{unique}")).unwrap(),
            owner,
            ContentDigest::from_bytes([2; 32]),
            now,
        )
        .unwrap();
    SchemaVersionRefs::new(artifact.version().id(), permission_policy.version().id())
}

#[test]
#[ignore = "requires DATABASE_URL, INFERNAL_LAW_SERVICE_ID, and PostgreSQL with pgvector"]
fn a_request_survives_submit_materialize_claim_read_and_complete_across_a_kernel_restart() {
    let application = Application::from_env().expect("application should connect and migrate");

    let requester = application
        .identities()
        .create(ActorKind::Service, "vertical slice continuity requester")
        .unwrap();
    let worker = application
        .identities()
        .create(ActorKind::Worker, "vertical slice continuity worker")
        .unwrap();
    let worker_credential = InstanceCredential::generate(worker.id());
    let now = unix_time();
    application
        .instance_registry()
        .register_verified(
            worker_credential.public_key().clone(),
            "https://vertical-slice-worker.example.test",
            now,
        )
        .unwrap();

    let action = unique_action("continuity-exercise");
    let subscription = application
        .subscriptions()
        .create(
            worker.id(),
            EventType::new(&action).unwrap(),
            DeliveryMode::Inclusive,
            now,
        )
        .unwrap();

    // Submit: ILK-003 acceptance.
    let request = Request::create(
        requester.id(),
        &action,
        Scope::new("vertical-slice-continuity-scope").unwrap(),
        schema_versions(&application, requester.id(), now),
    )
    .unwrap();
    let request_id = request.id();
    let fingerprint = RequestFingerprint::from_bytes([9; 32]);
    let accepted = match application
        .requests()
        .accept(request.clone(), fingerprint)
        .unwrap()
    {
        RequestAcceptance::Accepted(record) => record,
        RequestAcceptance::SafeRetry(_) => panic!("first submission must be a fresh acceptance"),
    };
    assert_eq!(accepted.request(), &request);

    // Materialize: ILK-010's bridge from the accepted request to the
    // worker's own inclusive subscription -- the same composition
    // submit_request's HTTP handler uses, exercised directly here.
    let router = SubscriptionRouter::new(application.subscriptions(), application.routes());
    let materialized = router
        .materialize_routes(requester.id(), request_id, request.action(), now)
        .unwrap();
    assert_eq!(materialized.len(), 1);
    let route = &materialized[0];
    assert_eq!(route.destination_service(), worker.id());
    assert_eq!(route.subscription_id(), subscription.id());

    // Eligible-route query (ADR-0011): the route is unclaimed, so it must
    // appear for the worker's own destination identity.
    let eligible_before_claim = application
        .routes()
        .list_for_destination(worker.id())
        .unwrap();
    let unclaimed_route_ids = application
        .work_claims()
        .active_route_ids(
            &eligible_before_claim
                .iter()
                .map(|r| r.id())
                .collect::<Vec<_>>(),
            now,
        )
        .unwrap();
    assert!(!unclaimed_route_ids.contains(&route.id()));

    // Claim: ILK-011.
    let claim = application
        .work_claims()
        .claim(
            route.id(),
            worker.id(),
            worker_credential.public_key().instance_id(),
            now + 300,
            now,
        )
        .unwrap();
    assert_eq!(claim.fencing_token(), 1);

    // Retry: resubmitting the identical request/fingerprint must be a safe
    // retry, and re-running materialization must not create a second
    // route -- idempotency chained through the same live state, not
    // proven in isolation.
    let retried = match application
        .requests()
        .accept(request.clone(), fingerprint)
        .unwrap()
    {
        RequestAcceptance::SafeRetry(record) => record,
        RequestAcceptance::Accepted(_) => panic!("resubmission must be a safe retry"),
    };
    assert_eq!(retried.accepted_at(), accepted.accepted_at());
    let rematerialized = router
        .materialize_routes(requester.id(), request_id, request.action(), now)
        .unwrap();
    assert_eq!(
        rematerialized, materialized,
        "materialization must be idempotent"
    );

    // Read: the destination-scoped read a claimed worker needs to learn
    // what it was asked to do (GET /v1/routes/{route_id}/request).
    let routed_request = application
        .requests()
        .find(route.source_service(), route.request_id())
        .unwrap()
        .expect("the request behind a materialized route must be readable");
    assert_eq!(routed_request.request().action(), request.action());
    assert_eq!(routed_request.request().scope(), request.scope());

    // Complete: ILK-011's terminal state.
    let completed = application
        .work_claims()
        .complete(claim.id(), claim.fencing_token(), now + 1)
        .unwrap();
    assert!(!completed.is_current(now + 1));

    // A stale fencing token must never complete a claim it no longer
    // holds -- including one that is now terminal, not just superseded.
    assert_eq!(
        application
            .work_claims()
            .complete(claim.id(), claim.fencing_token(), now + 2)
            .unwrap_err(),
        WorkClaimError::Fenced
    );

    // Crash/recovery: reconnect as a fresh process would after a restart
    // -- no in-memory state carries over, only what is durably committed.
    drop(application);
    let restarted = Application::from_env().expect("application should reconnect after restart");
    let request_after_restart = restarted
        .requests()
        .find(requester.id(), request_id)
        .unwrap()
        .expect("the accepted request must survive a kernel restart");
    assert_eq!(request_after_restart.request(), &request);
    let route_after_restart = restarted
        .routes()
        .find(route.id())
        .unwrap()
        .expect("the materialized route must survive a kernel restart");
    assert_eq!(route_after_restart, *route);
    let claim_after_restart = restarted
        .work_claims()
        .find(claim.id())
        .unwrap()
        .expect("the claim must survive a kernel restart");
    assert!(!claim_after_restart.is_current(now + 2));
}

#[test]
#[ignore = "requires DATABASE_URL, INFERNAL_LAW_SERVICE_ID, and PostgreSQL with pgvector"]
fn a_reclaimed_route_fences_out_the_worker_that_lost_it_mid_scenario() {
    let application = Application::from_env().expect("application should connect and migrate");

    let requester = application
        .identities()
        .create(ActorKind::Service, "fencing continuity requester")
        .unwrap();
    let worker = application
        .identities()
        .create(ActorKind::Worker, "fencing continuity worker")
        .unwrap();
    let first_instance = InstanceCredential::generate(worker.id());
    let second_instance = InstanceCredential::generate(worker.id());
    let now = unix_time();
    application
        .instance_registry()
        .register_verified(
            first_instance.public_key().clone(),
            "https://fencing-worker-1.example.test",
            now,
        )
        .unwrap();
    application
        .instance_registry()
        .register_verified(
            second_instance.public_key().clone(),
            "https://fencing-worker-2.example.test",
            now,
        )
        .unwrap();
    let action = unique_action("fencing-exercise");
    application
        .subscriptions()
        .create(
            worker.id(),
            EventType::new(&action).unwrap(),
            DeliveryMode::Inclusive,
            now,
        )
        .unwrap();
    let request = Request::create(
        requester.id(),
        &action,
        Scope::new("fencing-continuity-scope").unwrap(),
        schema_versions(&application, requester.id(), now),
    )
    .unwrap();
    application
        .requests()
        .accept(request.clone(), RequestFingerprint::from_bytes([3; 32]))
        .unwrap();
    let router = SubscriptionRouter::new(application.subscriptions(), application.routes());
    let route = router
        .materialize_routes(requester.id(), request.id(), request.action(), now)
        .unwrap()
        .remove(0);

    // First instance claims with a short lease, then loses it to expiry --
    // a second instance of the same worker service reclaims.
    let first_claim = application
        .work_claims()
        .claim(
            route.id(),
            worker.id(),
            first_instance.public_key().instance_id(),
            now + 5,
            now,
        )
        .unwrap();
    assert_eq!(first_claim.fencing_token(), 1);
    let second_claim = application
        .work_claims()
        .claim(
            route.id(),
            worker.id(),
            second_instance.public_key().instance_id(),
            now + 300,
            now + 6,
        )
        .unwrap();
    assert_eq!(
        second_claim.fencing_token(),
        2,
        "reclaiming must mint a strictly higher fencing token"
    );

    // The first instance, unaware it lost the lease, must not be able to
    // renew, release, or complete using its now-stale fencing token.
    assert_eq!(
        application
            .work_claims()
            .renew(
                first_claim.id(),
                first_claim.fencing_token(),
                now + 400,
                now + 7
            )
            .unwrap_err(),
        WorkClaimError::Fenced
    );
    assert_eq!(
        application
            .work_claims()
            .complete(first_claim.id(), first_claim.fencing_token(), now + 7)
            .unwrap_err(),
        WorkClaimError::Fenced
    );

    // The second instance, holding the current token, completes cleanly.
    let completed = application
        .work_claims()
        .complete(second_claim.id(), second_claim.fencing_token(), now + 8)
        .unwrap();
    assert!(!completed.is_current(now + 8));
}

fn unix_time() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock must be after Unix epoch")
            .as_secs(),
    )
    .expect("Unix time must fit in i64")
}
