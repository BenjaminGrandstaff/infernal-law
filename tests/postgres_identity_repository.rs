//! Goal: prove that ILK-001 identities survive PostgreSQL reconnection with
//! stable IDs and lifecycle state intact.

use infernal_law::infrastructure::postgres_identity_repository::PostgresIdentityRepository;
use infernal_law::kernel::identity::{
    ActorKind, IdentityError, IdentityRepository, IdentityStatus,
};
use infernal_law::wiring::Application;

#[test]
#[ignore = "requires DATABASE_URL, INFERNAL_LAW_SERVICE_ID, and PostgreSQL with pgvector"]
fn identity_survives_repository_restart_without_reusing_or_changing_its_id() {
    let first_process = Application::from_env().expect("first process should connect and migrate");
    let first_instance = first_process.instance_public_key().clone();
    let same_process_handle = first_process.clone();
    assert_eq!(
        same_process_handle.instance_public_key().instance_id(),
        first_instance.instance_id(),
        "threads in one process must share its one instance credential"
    );
    drop(same_process_handle);

    let created = first_process
        .identities()
        .create(ActorKind::Worker, "Durable identity")
        .expect("identity should be stored");
    let id = created.id();
    drop(first_process);

    let second_process = Application::from_env().expect("second process should reconnect");
    assert_eq!(
        second_process.instance_public_key().service_id(),
        first_instance.service_id(),
        "the configured service ID must remain stable"
    );
    assert_ne!(
        second_process.instance_public_key().instance_id(),
        first_instance.instance_id(),
        "a new process must receive a new instance credential"
    );
    let restored = second_process
        .identities()
        .resolve_active(id)
        .expect("identity should survive reconnection");
    assert_eq!(restored, created);

    let duplicate_repository = PostgresIdentityRepository::new(second_process.database().clone());
    assert_eq!(
        duplicate_repository.insert(created.clone()).unwrap_err(),
        IdentityError::AlreadyExists(id)
    );

    let renamed = second_process
        .identities()
        .rename(id, "Durable identity renamed")
        .expect("identity metadata should update");
    assert_eq!(renamed.id(), id);
    second_process
        .identities()
        .disable(id)
        .expect("identity should be disabled");
    drop(second_process);

    let third_process = Application::from_env().expect("third process should reconnect");
    let disabled = third_process
        .identities()
        .find(id)
        .expect("query should succeed")
        .expect("identity should still exist");
    assert_eq!(disabled.id(), id);
    assert_eq!(disabled.status(), IdentityStatus::Disabled);
    assert_eq!(
        third_process.identities().resolve_active(id).unwrap_err(),
        IdentityError::Disabled(id)
    );
}
