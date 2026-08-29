//! Goal: prove replay reservations, request bindings, rejection audits, and
//! append-only guards survive in live PostgreSQL.

use std::env;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use infernal_law::kernel::identity::ActorKind;
use infernal_law::kernel::instance_keys::InstanceCredential;
use infernal_law::kernel::replay_protection::{ReplayDisposition, ReplayProtectionError};
use infernal_law::kernel::service_requests::{ServiceRequestParts, SignedServiceRequest};
use infernal_law::wiring::Application;
use r2d2_postgres::postgres::{Client, NoTls};
use uuid::Uuid;

#[test]
#[ignore = "requires DATABASE_URL, INFERNAL_LAW_SERVICE_ID, and PostgreSQL with pgvector"]
fn replay_state_is_atomic_audited_and_append_only() {
    let application = Application::from_env().expect("application should connect and migrate");
    let service = application
        .identities()
        .create(ActorKind::Worker, "Replay protection integration worker")
        .unwrap();
    let credential = InstanceCredential::generate(service.id());
    let now = unix_time();
    application
        .instance_registry()
        .register_verified(
            credential.public_key().clone(),
            "https://replay-worker.example.test",
            now,
        )
        .unwrap();

    let request_id = Uuid::new_v4();
    let first = verified(
        &application,
        &credential,
        request_id,
        br#"{"value":1}"#,
        "postgres_nonce_0001",
        now,
    );
    let retry = verified(
        &application,
        &credential,
        request_id,
        br#"{"value":1}"#,
        "postgres_nonce_0002",
        now,
    );
    let conflict = verified(
        &application,
        &credential,
        request_id,
        br#"{"value":2}"#,
        "postgres_nonce_0003",
        now,
    );

    assert_eq!(
        application.replay_protection().protect(first, now),
        Ok(ReplayDisposition::Fresh)
    );
    assert_eq!(
        application.replay_protection().protect(retry, now),
        Ok(ReplayDisposition::SafeRetry)
    );
    assert_eq!(
        application.replay_protection().protect(conflict, now),
        Err(ReplayProtectionError::RequestIdConflict)
    );
    assert_eq!(
        application.replay_protection().protect(first, now),
        Err(ReplayProtectionError::ReplayDetected)
    );

    let concurrent_request_id = Uuid::new_v4();
    let concurrent = verified(
        &application,
        &credential,
        concurrent_request_id,
        br#"{"concurrent":true}"#,
        "postgres_nonce_0004",
        now,
    );
    let outcomes: Vec<_> = (0..8)
        .map(|_| {
            let protection = application.replay_protection().clone();
            thread::spawn(move || protection.protect(concurrent, now))
        })
        .map(|thread| thread.join().unwrap())
        .collect();
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome == Ok(ReplayDisposition::Fresh))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome == Err(ReplayProtectionError::ReplayDetected))
            .count(),
        7
    );

    assert_database_history(service.id().to_string(), request_id.to_string());
    assert_concurrent_history(service.id().to_string(), concurrent_request_id.to_string());
}

fn verified(
    application: &Application,
    credential: &InstanceCredential,
    request_id: Uuid,
    body: &[u8],
    nonce: &str,
    now: i64,
) -> infernal_law::kernel::service_requests::VerifiedServiceRequest {
    let parts = ServiceRequestParts::new(
        "POST",
        "kernel.example.test",
        "/v1/subscriptions",
        "application/json",
        body,
        request_id,
    )
    .unwrap();
    let signed = SignedServiceRequest::sign(parts, credential, now, now + 30, nonce).unwrap();
    application
        .service_request_verifier()
        .verify(&signed, now)
        .unwrap()
}

fn assert_database_history(service_id: String, request_id: String) {
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be present");
    let mut client = Client::connect(&database_url, NoTls).expect("test database should connect");
    let request_count: i64 = client
        .query_one(
            "SELECT count(*) FROM service_request_ids \
             WHERE service_id = $1::text::uuid AND request_id = $2::text::uuid",
            &[&service_id, &request_id],
        )
        .unwrap()
        .get(0);
    let nonce_count: i64 = client
        .query_one(
            "SELECT count(*) FROM service_request_nonces \
             WHERE service_id = $1::text::uuid AND request_id = $2::text::uuid",
            &[&service_id, &request_id],
        )
        .unwrap()
        .get(0);
    let outcomes: Vec<String> = client
        .query(
            "SELECT outcome FROM service_request_replay_audit \
             WHERE service_id = $1::text::uuid AND request_id = $2::text::uuid \
             ORDER BY audit_id",
            &[&service_id, &request_id],
        )
        .unwrap()
        .iter()
        .map(|row| row.get(0))
        .collect();

    assert_eq!(request_count, 1);
    assert_eq!(
        nonce_count, 3,
        "conflicting fresh nonces are still consumed"
    );
    assert_eq!(
        outcomes,
        [
            "fresh",
            "safe_retry",
            "request_conflict_rejected",
            "replay_rejected"
        ]
    );
    assert!(
        client
            .execute(
                "DELETE FROM service_request_ids \
                 WHERE service_id = $1::text::uuid AND request_id = $2::text::uuid",
                &[&service_id, &request_id],
            )
            .is_err(),
        "request-ID bindings must be append-only"
    );
    assert!(
        client
            .execute(
                "DELETE FROM service_request_nonces \
                 WHERE service_id = $1::text::uuid AND request_id = $2::text::uuid",
                &[&service_id, &request_id],
            )
            .is_err(),
        "nonce history must be append-only"
    );
    assert!(
        client
            .execute(
                "DELETE FROM service_request_replay_audit \
                 WHERE service_id = $1::text::uuid AND request_id = $2::text::uuid",
                &[&service_id, &request_id],
            )
            .is_err(),
        "replay audit must be append-only"
    );
}

fn assert_concurrent_history(service_id: String, request_id: String) {
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be present");
    let mut client = Client::connect(&database_url, NoTls).expect("test database should connect");
    let row = client
        .query_one(
            "SELECT \
                (SELECT count(*) FROM service_request_ids \
                 WHERE service_id = $1::text::uuid AND request_id = $2::text::uuid), \
                (SELECT count(*) FROM service_request_nonces \
                 WHERE service_id = $1::text::uuid AND request_id = $2::text::uuid), \
                (SELECT count(*) FROM service_request_replay_audit \
                 WHERE service_id = $1::text::uuid AND request_id = $2::text::uuid \
                   AND outcome = 'fresh'), \
                (SELECT count(*) FROM service_request_replay_audit \
                 WHERE service_id = $1::text::uuid AND request_id = $2::text::uuid \
                   AND outcome = 'replay_rejected')",
            &[&service_id, &request_id],
        )
        .unwrap();
    assert_eq!(row.get::<_, i64>(0), 1);
    assert_eq!(row.get::<_, i64>(1), 1);
    assert_eq!(row.get::<_, i64>(2), 1);
    assert_eq!(row.get::<_, i64>(3), 7);
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
