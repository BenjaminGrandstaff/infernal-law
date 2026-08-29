//! Goal: prove accepted requests, safe retries, conflicts, concurrency, and
//! append-only guards survive process replacement in live PostgreSQL.

use std::env;
use std::thread;

use infernal_law::kernel::identity::{ActorId, ActorKind};
use infernal_law::kernel::requests::{
    Request, RequestAcceptance, RequestError, RequestFingerprint, RequestId,
};
use infernal_law::wiring::Application;
use r2d2_postgres::postgres::{Client, NoTls};

#[test]
#[ignore = "requires DATABASE_URL, INFERNAL_LAW_SERVICE_ID, and PostgreSQL with pgvector"]
fn accepted_requests_survive_restart_and_reject_duplicate_or_destructive_work() {
    let first_process = Application::from_env().expect("application should connect and migrate");
    let source = first_process
        .identities()
        .create(ActorKind::Service, "Request persistence integration source")
        .unwrap();
    let request = Request::create(source.id(), "billing.invoice.submit").unwrap();
    let fingerprint = RequestFingerprint::from_bytes([11; 32]);

    let accepted = first_process
        .requests()
        .accept(request.clone(), fingerprint)
        .unwrap();
    assert!(accepted.is_fresh());
    assert!(accepted.record().accepted_at() >= 0);
    drop(first_process);

    let second_process = Application::from_env().expect("replacement process should reconnect");
    assert_eq!(
        second_process
            .requests()
            .find(source.id(), request.id())
            .unwrap(),
        Some(accepted.record().clone())
    );
    let retry = second_process
        .requests()
        .accept(request.clone(), fingerprint)
        .unwrap();
    assert!(matches!(retry, RequestAcceptance::SafeRetry(_)));
    assert_eq!(retry.record(), accepted.record());

    let conflicting =
        Request::restore(request.id(), source.id(), "billing.invoice.cancel").unwrap();
    assert_eq!(
        second_process
            .requests()
            .accept(conflicting, RequestFingerprint::from_bytes([12; 32])),
        Err(RequestError::RequestIdConflict(request.id()))
    );

    let unknown_source = ActorId::new();
    assert_eq!(
        second_process.requests().accept(
            Request::create(unknown_source, "billing.invoice.submit").unwrap(),
            fingerprint,
        ),
        Err(RequestError::UnknownSource(unknown_source))
    );

    assert_concurrent_acceptance(&second_process, source.id());
    assert_database_history_and_guards(source.id(), request.id());
}

fn assert_concurrent_acceptance(application: &Application, source: ActorId) {
    let request = Request::create(source, "work.item.submit").unwrap();
    let requests = application.requests().clone();
    let outcomes: Vec<_> = (0..8)
        .map(|_| {
            let requests = requests.clone();
            let request = request.clone();
            thread::spawn(move || {
                requests.accept(request, RequestFingerprint::from_bytes([13; 32]))
            })
        })
        .map(|handle| handle.join().unwrap().unwrap())
        .collect();

    assert_eq!(outcomes.iter().filter(|value| value.is_fresh()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|value| matches!(value, RequestAcceptance::SafeRetry(_)))
            .count(),
        7
    );
    let first = outcomes[0].record();
    assert!(outcomes.iter().all(|value| value.record() == first));
}

fn assert_database_history_and_guards(source: ActorId, request_id: RequestId) {
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be present");
    let mut client = Client::connect(&database_url, NoTls).expect("test database should connect");
    let source = source.to_string();
    let request_id = request_id.to_string();
    let row = client
        .query_one(
            "SELECT \
                (SELECT count(*) FROM accepted_requests \
                 WHERE source_service_id = $1::text::uuid \
                   AND request_id = $2::text::uuid), \
                (SELECT count(*) FROM request_acceptance_audit \
                 WHERE source_service_id = $1::text::uuid \
                   AND request_id = $2::text::uuid AND outcome = 'accepted'), \
                (SELECT count(*) FROM request_acceptance_audit \
                 WHERE source_service_id = $1::text::uuid \
                   AND request_id = $2::text::uuid AND outcome = 'safe_retry'), \
                (SELECT count(*) FROM request_acceptance_audit \
                 WHERE source_service_id = $1::text::uuid \
                   AND request_id = $2::text::uuid \
                   AND outcome = 'request_conflict_rejected')",
            &[&source, &request_id],
        )
        .unwrap();
    assert_eq!(row.get::<_, i64>(0), 1);
    assert_eq!(row.get::<_, i64>(1), 1);
    assert_eq!(row.get::<_, i64>(2), 1);
    assert_eq!(row.get::<_, i64>(3), 1);

    assert!(
        client
            .execute(
                "UPDATE accepted_requests SET action = 'changed.action' \
                 WHERE source_service_id = $1::text::uuid \
                   AND request_id = $2::text::uuid",
                &[&source, &request_id],
            )
            .is_err(),
        "accepted requests must be immutable"
    );
    assert!(
        client
            .execute(
                "DELETE FROM accepted_requests \
                 WHERE source_service_id = $1::text::uuid \
                   AND request_id = $2::text::uuid",
                &[&source, &request_id],
            )
            .is_err(),
        "accepted requests must be append-only"
    );
    assert!(
        client
            .execute(
                "DELETE FROM request_acceptance_audit \
                 WHERE source_service_id = $1::text::uuid \
                   AND request_id = $2::text::uuid",
                &[&source, &request_id],
            )
            .is_err(),
        "request acceptance audit must be append-only"
    );
}
