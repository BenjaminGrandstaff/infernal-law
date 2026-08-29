//! Goal: prove communication admission defaults to deny, changes only through
//! the out-of-band database function, and retains immutable idempotent history.

use std::env;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use infernal_law::kernel::admission::AdmissionError;
use infernal_law::kernel::identity::{ActorKind, IdentityStatus};
use infernal_law::wiring::Application;
use r2d2_postgres::postgres::{Client, NoTls, Row};
use uuid::Uuid;

#[test]
#[ignore = "requires DATABASE_URL, INFERNAL_LAW_SERVICE_ID, and PostgreSQL with pgvector"]
fn admission_defaults_deny_and_admin_changes_are_idempotent_and_append_only() {
    let application = Application::from_env().expect("application should connect and migrate");
    let identity = application
        .identities()
        .create(ActorKind::Worker, "Admission integration worker")
        .unwrap();
    let service_id = identity.id();
    assert_eq!(identity.status(), IdentityStatus::Active);
    assert_eq!(
        application.admission().require_enabled(service_id),
        Err(AdmissionError::Disabled(service_id)),
        "a new active identity must still be denied communication"
    );

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be present");
    let mut administrator =
        Client::connect(&database_url, NoTls).expect("test database should connect");
    let now: i64 = administrator
        .query_one(
            "SELECT greatest(updated_at, $2) \
             FROM service_communication_admission \
             WHERE service_id = $1::text::uuid",
            &[&service_id.to_string(), &unix_time()],
        )
        .unwrap()
        .get(0);
    let enable_correlation = Uuid::new_v4();
    let enabled = administer(
        &mut administrator,
        service_id.to_string(),
        true,
        "test-administrator",
        "enable integration worker",
        enable_correlation.to_string(),
        now,
    );
    assert_change(&enabled, true, 1, now, "changed");
    let admitted = application.admission().require_enabled(service_id).unwrap();
    assert!(admitted.is_enabled());
    assert_eq!(admitted.revision(), 1);

    let idempotent = administer(
        &mut administrator,
        service_id.to_string(),
        true,
        "test-administrator",
        "enable integration worker",
        enable_correlation.to_string(),
        now,
    );
    assert_change(&idempotent, true, 1, now, "changed");
    assert!(
        administrator
            .query_one(
                "SELECT * FROM set_service_communication_admission( \
                 $1::text::uuid, $2, $3, $4, $5::text::uuid, $6)",
                &[
                    &service_id.to_string(),
                    &true,
                    &"test-administrator",
                    &"different reason",
                    &enable_correlation.to_string(),
                    &now,
                ],
            )
            .is_err(),
        "one correlation ID cannot authorize different administration metadata"
    );

    let no_op_correlation = Uuid::new_v4();
    let no_op = administer(
        &mut administrator,
        service_id.to_string(),
        true,
        "test-administrator",
        "confirm desired state",
        no_op_correlation.to_string(),
        now + 1,
    );
    assert_change(&no_op, true, 1, now + 1, "no_op");

    let disable_correlation = Uuid::new_v4();
    let disabled = administer(
        &mut administrator,
        service_id.to_string(),
        false,
        "test-administrator",
        "disable integration worker",
        disable_correlation.to_string(),
        now + 2,
    );
    assert_change(&disabled, false, 2, now + 2, "changed");
    assert_eq!(
        application.admission().require_enabled(service_id),
        Err(AdmissionError::Disabled(service_id))
    );

    let concurrent_correlation = Uuid::new_v4();
    let concurrent_results: Vec<_> = (0..6)
        .map(|_| {
            let database_url = database_url.clone();
            let service_id = service_id.to_string();
            let correlation_id = concurrent_correlation.to_string();
            thread::spawn(move || {
                let mut client = Client::connect(&database_url, NoTls).unwrap();
                let row = administer(
                    &mut client,
                    service_id,
                    false,
                    "test-administrator",
                    "concurrent desired-state confirmation",
                    correlation_id,
                    now + 3,
                );
                (
                    row.get::<_, bool>("result_enabled"),
                    row.get::<_, i64>("result_revision"),
                    row.get::<_, i64>("result_changed_at"),
                    row.get::<_, String>("result_outcome"),
                )
            })
        })
        .map(|thread| thread.join().unwrap())
        .collect();
    assert!(
        concurrent_results
            .iter()
            .all(|result| { result == &(false, 2, now + 3, "no_op".to_owned()) })
    );

    assert_database_guards(&mut administrator, service_id.to_string());
}

#[allow(clippy::too_many_arguments)]
fn administer(
    administrator: &mut Client,
    service_id: String,
    enabled: bool,
    administrator_identity: &str,
    reason: &str,
    correlation_id: String,
    changed_at: i64,
) -> Row {
    administrator
        .query_one(
            "SELECT * FROM set_service_communication_admission( \
             $1::text::uuid, $2, $3, $4, $5::text::uuid, $6)",
            &[
                &service_id,
                &enabled,
                &administrator_identity,
                &reason,
                &correlation_id,
                &changed_at,
            ],
        )
        .unwrap()
}

fn assert_change(row: &Row, enabled: bool, revision: i64, changed_at: i64, outcome: &str) {
    assert_eq!(row.get::<_, bool>("result_enabled"), enabled);
    assert_eq!(row.get::<_, i64>("result_revision"), revision);
    assert_eq!(row.get::<_, i64>("result_changed_at"), changed_at);
    assert_eq!(row.get::<_, String>("result_outcome"), outcome);
}

fn assert_database_guards(administrator: &mut Client, service_id: String) {
    let history_count: i64 = administrator
        .query_one(
            "SELECT count(*) FROM service_communication_admission_history \
             WHERE service_id = $1::text::uuid",
            &[&service_id],
        )
        .unwrap()
        .get(0);
    assert_eq!(
        history_count, 4,
        "sequential and concurrent retries must not duplicate history"
    );
    assert!(
        administrator
            .execute(
                "UPDATE service_communication_admission \
                 SET communication_enabled = true \
                 WHERE service_id = $1::text::uuid",
                &[&service_id],
            )
            .is_err(),
        "direct updates must be rejected even for the migration owner"
    );
    assert!(
        administrator
            .execute(
                "DELETE FROM service_communication_admission \
                 WHERE service_id = $1::text::uuid",
                &[&service_id],
            )
            .is_err(),
        "admission state must not be silently deleted"
    );
    assert!(
        administrator
            .execute(
                "DELETE FROM service_communication_admission_history \
                 WHERE service_id = $1::text::uuid",
                &[&service_id],
            )
            .is_err(),
        "admission history must be append-only"
    );
    let function_acl: String = administrator
        .query_one(
            "SELECT coalesce(proacl::text, '') FROM pg_proc \
             WHERE oid = 'set_service_communication_admission( \
                 uuid,boolean,text,text,uuid,bigint)'::regprocedure",
            &[],
        )
        .unwrap()
        .get(0);
    assert!(
        !function_acl
            .trim_matches(['{', '}'])
            .split(',')
            .any(|grant| grant.starts_with("=X/")),
        "PUBLIC must not execute the administrative function"
    );
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
