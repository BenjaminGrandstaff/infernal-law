//! Goal: prove the real PostgreSQL-backed HTTP gate composes signature,
//! replay, and admission state in order through application wiring.

use std::env;
use std::time::{SystemTime, UNIX_EPOCH};

use infernal_law::http::{GovernedHttpRequest, authenticate_governed_request};
use infernal_law::kernel::identity::ActorKind;
use infernal_law::kernel::instance_keys::InstanceCredential;
use infernal_law::kernel::replay_protection::ReplayDisposition;
use infernal_law::kernel::service_requests::{ServiceRequestParts, SignedServiceRequest};
use infernal_law::wiring::Application;
use r2d2_postgres::postgres::{Client, NoTls};
use uuid::Uuid;

#[test]
#[ignore = "requires DATABASE_URL, INFERNAL_LAW_SERVICE_ID, and PostgreSQL with pgvector"]
fn governed_http_gate_uses_live_signature_replay_and_admission_state() {
    let application = Application::from_env().expect("application should connect and migrate");
    let service = application
        .identities()
        .create(ActorKind::Worker, "Governed HTTP integration worker")
        .unwrap();
    let credential = InstanceCredential::generate(service.id());
    let database_url = env::var("DATABASE_URL").unwrap();
    let mut administrator = Client::connect(&database_url, NoTls).unwrap();
    let now: i64 = administrator
        .query_one(
            "SELECT greatest(updated_at, $2) FROM service_communication_admission \
             WHERE service_id = $1::text::uuid",
            &[&service.id().to_string(), &unix_time()],
        )
        .unwrap()
        .get(0);
    application
        .instance_registry()
        .register_verified(
            credential.public_key().clone(),
            "https://governed-http-worker.example.test",
            now,
        )
        .unwrap();
    administer(
        &mut administrator,
        service.id().to_string(),
        true,
        Uuid::new_v4().to_string(),
        now,
    );

    let request_id = Uuid::new_v4();
    let first = signed(&credential, request_id, "live_middleware_001", now);
    let first_result = authenticate(&application, &first, now).unwrap();
    assert_eq!(first_result.replay_disposition(), ReplayDisposition::Fresh);

    let replay = authenticate(&application, &first, now).unwrap_err();
    assert_eq!(replay.status, "401 Unauthorized");

    let retry = signed(&credential, request_id, "live_middleware_002", now);
    let retry_result = authenticate(&application, &retry, now).unwrap();
    assert_eq!(
        retry_result.replay_disposition(),
        ReplayDisposition::SafeRetry
    );

    administer(
        &mut administrator,
        service.id().to_string(),
        false,
        Uuid::new_v4().to_string(),
        now + 1,
    );
    let denied_request_id = Uuid::new_v4();
    let denied = signed(&credential, denied_request_id, "live_middleware_003", now);
    let denial = authenticate(&application, &denied, now).unwrap_err();
    assert_eq!(denial.status, "403 Forbidden");

    let reserved_before_denial: i64 = administrator
        .query_one(
            "SELECT count(*) FROM service_request_nonces \
             WHERE service_id = $1::text::uuid AND request_id = $2::text::uuid",
            &[&service.id().to_string(), &denied_request_id.to_string()],
        )
        .unwrap()
        .get(0);
    assert_eq!(
        reserved_before_denial, 1,
        "the nonce must be consumed before the admission check"
    );
}

fn signed(
    credential: &InstanceCredential,
    request_id: Uuid,
    nonce: &str,
    now: i64,
) -> SignedServiceRequest {
    let parts = ServiceRequestParts::new(
        "GET",
        "kernel.example.test",
        "/v1/subscriptions",
        "application/json",
        b"",
        request_id,
    )
    .unwrap();
    SignedServiceRequest::sign(parts, credential, now, now + 30, nonce).unwrap()
}

fn authenticate(
    application: &Application,
    signed: &SignedServiceRequest,
    now: i64,
) -> Result<infernal_law::kernel::request_gate::AdmittedServiceRequest, infernal_law::http::Response>
{
    let service_id = signed.service_id().to_string();
    let instance_id = signed.instance_id().to_string();
    let request_id = signed.parts().request_id().to_string();
    authenticate_governed_request(
        GovernedHttpRequest {
            method: "GET",
            authority: "kernel.example.test",
            path_and_query: "/v1/subscriptions",
            content_type: "application/json",
            body: b"",
            service_id: &service_id,
            instance_id: &instance_id,
            request_id: &request_id,
            content_digest: signed.content_digest(),
            signature_input: signed.signature_input(),
            signature: signed.signature(),
        },
        &application.service_request_gate(),
        now,
    )
}

fn administer(
    administrator: &mut Client,
    service_id: String,
    enabled: bool,
    correlation_id: String,
    changed_at: i64,
) {
    administrator
        .query_one(
            "SELECT * FROM set_service_communication_admission( \
             $1::text::uuid, $2, $3, $4, $5::text::uuid, $6)",
            &[
                &service_id,
                &enabled,
                &"integration-administrator",
                &"governed HTTP integration state",
                &correlation_id,
                &changed_at,
            ],
        )
        .unwrap();
}

fn unix_time() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock must be after Unix epoch")
            .as_secs(),
    )
    .expect("Unix time must fit in i64")
}
