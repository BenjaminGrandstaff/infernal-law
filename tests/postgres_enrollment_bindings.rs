//! Goal: prove workload bindings and one-time enrollment challenges retain
//! their security semantics in PostgreSQL.

use std::time::{SystemTime, UNIX_EPOCH};

use infernal_law::infrastructure::postgres_enrollment_binding_repository::PostgresEnrollmentBindingRepository;
use infernal_law::kernel::enrollment::{
    EnrollmentBinding, EnrollmentBindingRepository, EnrollmentChallenge, EnrollmentError,
};
use infernal_law::kernel::identity::ActorKind;
use infernal_law::wiring::Application;

#[test]
#[ignore = "requires DATABASE_URL, INFERNAL_LAW_SERVICE_ID, and PostgreSQL with pgvector"]
fn binding_is_disabled_by_default_and_challenge_is_single_use() {
    let application = Application::from_env().expect("application should connect and migrate");
    let service = application
        .identities()
        .create(ActorKind::Service, "Enrollment integration service")
        .expect("service identity should be stored");
    let repository = PostgresEnrollmentBindingRepository::new(application.database().clone());
    let binding = EnrollmentBinding::new_disabled(
        service.id(),
        "workers",
        "indexer",
        &format!("sa-{}", service.id()),
    )
    .unwrap();
    let service_account_uid = binding.service_account_uid().to_owned();
    repository.insert_disabled(binding).unwrap();

    let stored = repository
        .find_workload("workers", "indexer", &service_account_uid)
        .unwrap()
        .unwrap();
    assert!(!stored.enabled());
    repository.set_enabled(service.id(), true).unwrap();
    assert!(
        repository
            .find_workload("workers", "indexer", &service_account_uid)
            .unwrap()
            .unwrap()
            .enabled()
    );

    let challenge = EnrollmentChallenge::generate();
    let now = unix_time();
    repository
        .insert_challenge(service.id(), challenge, now + 30)
        .unwrap();
    repository
        .consume_challenge(service.id(), challenge, now)
        .unwrap();
    assert_eq!(
        repository.consume_challenge(service.id(), challenge, now + 1),
        Err(EnrollmentError::ChallengeRejected)
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
