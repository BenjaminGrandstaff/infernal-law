//! Goal: prove ILK-011 work claims are atomic, fenced, and append-only
//! (status transitions once, terminally) in live PostgreSQL.

use std::collections::HashSet;
use std::env;

use infernal_law::infrastructure::postgres_authority_repository::PostgresAuthorityRepository;
use infernal_law::kernel::authority::{
    ContentDigest, SchemaKind, SchemaName, SchemaRepository, SchemaVersionRefs, Scope,
};
use infernal_law::kernel::identity::{ActorId, ActorKind};
use infernal_law::kernel::instance_keys::InstanceCredential;
use infernal_law::kernel::requests::Request;
use infernal_law::kernel::subscriptions::{DeliveryMode, EventType};
use infernal_law::kernel::work_claims::WorkClaimError;
use infernal_law::wiring::Application;
use r2d2_postgres::postgres::{Client, NoTls};

fn publish_schema_versions(
    application: &Application,
    owner: ActorId,
    name: &str,
    discriminant: u8,
) -> SchemaVersionRefs {
    let repository = PostgresAuthorityRepository::new(application.database().clone());
    let name = SchemaName::new(name).unwrap();
    let artifact = repository
        .publish(
            SchemaKind::Artifact,
            name.clone(),
            owner,
            ContentDigest::from_bytes([discriminant; 32]),
            1,
        )
        .unwrap();
    let permission_policy = repository
        .publish(
            SchemaKind::PermissionPolicy,
            name,
            owner,
            ContentDigest::from_bytes([discriminant; 32]),
            1,
        )
        .unwrap();
    SchemaVersionRefs::new(artifact.version().id(), permission_policy.version().id())
}

#[test]
#[ignore = "requires DATABASE_URL, INFERNAL_LAW_SERVICE_ID, and PostgreSQL with pgvector"]
fn work_claims_are_atomic_fenced_and_append_only() {
    let application = Application::from_env().expect("application should connect and migrate");
    let source = application
        .identities()
        .create(ActorKind::Service, "Work claim integration source")
        .unwrap();
    let destination = application
        .identities()
        .create(ActorKind::Service, "Work claim integration destination")
        .unwrap();
    let worker_credential = InstanceCredential::generate(destination.id());
    let worker_instance = application
        .instance_registry()
        .register_verified(
            worker_credential.public_key().clone(),
            "https://work-claim-integration-worker.example.test",
            1,
        )
        .unwrap()
        .public_key()
        .instance_id();

    let event_type = EventType::new("test.work-claim.v1").unwrap();
    let subscription = application
        .subscriptions()
        .create(destination.id(), event_type, DeliveryMode::Inclusive, 1)
        .unwrap();
    let schema_versions = publish_schema_versions(&application, source.id(), "test.work-claim", 41);
    let request = Request::create(
        source.id(),
        "test.work-claim.v1",
        Scope::wildcard(),
        schema_versions,
    )
    .unwrap();
    let fingerprint = request.fingerprint();
    let accepted = application.requests().accept(request, fingerprint).unwrap();
    let route = application
        .routes()
        .materialize(
            source.id(),
            accepted.record().request().id(),
            subscription.id(),
            destination.id(),
            2,
        )
        .unwrap();

    let first = application
        .work_claims()
        .claim(route.id(), destination.id(), worker_instance, 100, 10)
        .unwrap();
    assert_eq!(first.fencing_token(), 1);
    assert_eq!(
        application
            .work_claims()
            .active_route_ids(&[route.id()], 10)
            .unwrap(),
        HashSet::from([route.id()])
    );

    assert_eq!(
        application
            .work_claims()
            .claim(route.id(), destination.id(), worker_instance, 200, 20),
        Err(WorkClaimError::AlreadyClaimed(route.id()))
    );

    let renewed = application
        .work_claims()
        .renew(first.id(), first.fencing_token(), 300, 30)
        .unwrap();
    assert_eq!(renewed.fencing_token(), 1);
    assert_eq!(renewed.lease_expires_at(), 300);

    let unrelated_worker = application
        .identities()
        .create(
            ActorKind::Service,
            "Work claim integration unrelated worker",
        )
        .unwrap();
    assert_eq!(
        application.work_claims().claim(
            route.id(),
            unrelated_worker.id(),
            worker_instance,
            400,
            40
        ),
        Err(WorkClaimError::RouteNotFound(route.id()))
    );

    let completed = application
        .work_claims()
        .complete(first.id(), first.fencing_token(), 40)
        .unwrap();
    assert_eq!(
        application
            .work_claims()
            .renew(completed.id(), completed.fencing_token(), 500, 41),
        Err(WorkClaimError::Fenced)
    );
    assert!(
        application
            .work_claims()
            .active_route_ids(&[route.id()], 40)
            .unwrap()
            .is_empty(),
        "a completed claim must not make its route look currently claimed"
    );

    let second = application
        .work_claims()
        .claim(route.id(), destination.id(), worker_instance, 600, 50)
        .unwrap();
    assert_eq!(second.fencing_token(), 2);
    assert_eq!(
        application
            .work_claims()
            .active_route_ids(&[route.id()], 50)
            .unwrap(),
        HashSet::from([route.id()])
    );

    assert_database_guards(first.id(), second.id());
}

fn assert_database_guards(
    completed_claim_id: infernal_law::kernel::work_claims::ClaimId,
    active_claim_id: infernal_law::kernel::work_claims::ClaimId,
) {
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be present");
    let mut client = Client::connect(&database_url, NoTls).expect("test database should connect");

    assert!(
        client
            .execute(
                "DELETE FROM work_claims WHERE claim_id = $1::text::uuid",
                &[&completed_claim_id.to_string()],
            )
            .is_err(),
        "work claims must never be deleted"
    );
    assert!(
        client
            .execute(
                "UPDATE work_claims SET status = 'active' \
                 WHERE claim_id = $1::text::uuid",
                &[&completed_claim_id.to_string()],
            )
            .is_err(),
        "a terminal work claim status must never revert"
    );
    assert!(
        client
            .execute(
                "UPDATE work_claims SET fencing_token = fencing_token + 1 \
                 WHERE claim_id = $1::text::uuid",
                &[&active_claim_id.to_string()],
            )
            .is_err(),
        "fencing token must be immutable on an existing row"
    );
}
