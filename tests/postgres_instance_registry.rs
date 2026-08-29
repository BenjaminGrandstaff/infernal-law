//! Goal: prove public instance keys, leases, and revocation survive PostgreSQL
//! reconnection without storing private keys.

use std::env;
use std::time::{SystemTime, UNIX_EPOCH};

use infernal_law::infrastructure::postgres_instance_registry::PostgresInstanceRegistry;
use infernal_law::kernel::identity::ActorKind;
use infernal_law::kernel::instance_keys::InstanceCredential;
use infernal_law::kernel::instance_registry::{InstanceRegistryError, InstanceRegistryRepository};
use infernal_law::wiring::Application;
use r2d2_postgres::postgres::{Client, NoTls};

#[test]
#[ignore = "requires DATABASE_URL, INFERNAL_LAW_SERVICE_ID, and PostgreSQL with pgvector"]
fn public_key_lease_survives_reconnection_and_revocation() {
    let first_process = Application::from_env().expect("first process should connect and migrate");
    let service = first_process
        .identities()
        .create(ActorKind::Service, "Registry integration service")
        .expect("service identity should be stored");
    let credential = InstanceCredential::generate(service.id());
    let now = unix_time();
    let registered = first_process
        .instance_registry()
        .register_verified(
            credential.public_key().clone(),
            "https://registry-test.example.test",
            now,
        )
        .expect("public key and lease should register");
    let instance_id = registered.public_key().instance_id();
    assert_eq!(
        first_process.instance_registry().register_verified(
            credential.public_key().clone(),
            "https://registry-test.example.test",
            now,
        ),
        Err(InstanceRegistryError::AlreadyExists(instance_id))
    );

    let unknown_service =
        InstanceCredential::generate(infernal_law::kernel::identity::ActorId::new());
    assert_eq!(
        first_process.instance_registry().register_verified(
            unknown_service.public_key().clone(),
            "https://unknown.example.test",
            now,
        ),
        Err(InstanceRegistryError::UnknownService(
            unknown_service.public_key().service_id()
        ))
    );
    drop(first_process);

    let second_process = Application::from_env().expect("second process should reconnect");
    let restored = second_process
        .instance_registry()
        .find_eligible(instance_id, now + 1)
        .expect("unexpired public key should survive reconnection");
    assert_eq!(restored, registered);

    let renewed = second_process
        .instance_registry()
        .renew(instance_id, 1, now + 2)
        .expect("current lease revision should renew");
    assert_eq!(renewed.lease_revision(), 2);
    assert_eq!(
        second_process
            .instance_registry()
            .renew(instance_id, 1, now + 3),
        Err(InstanceRegistryError::RevisionConflict(instance_id))
    );

    second_process
        .instance_registry()
        .revoke(instance_id, now + 4)
        .expect("active instance should revoke");
    assert_eq!(
        second_process
            .instance_registry()
            .find_eligible(instance_id, now + 5),
        Err(InstanceRegistryError::Revoked(instance_id))
    );

    assert_database_guards(second_process.database().clone(), instance_id);
}

fn assert_database_guards(
    database: infernal_law::infrastructure::database::Database,
    instance_id: infernal_law::kernel::instance_keys::InstanceId,
) {
    let repository = PostgresInstanceRegistry::new(database);
    assert!(repository.find(instance_id).unwrap().is_some());

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be present");
    let mut client = Client::connect(&database_url, NoTls).expect("test database should connect");
    let id = instance_id.to_string();
    let audit_count: i64 = client
        .query_one(
            "SELECT count(*) FROM service_instance_registry_audit \
             WHERE instance_id = $1::text::uuid",
            &[&id],
        )
        .expect("audit rows should be queryable")
        .get(0);
    assert_eq!(
        audit_count, 3,
        "register, renew, and revoke must be audited"
    );

    let mutation = client.execute(
        "UPDATE service_instance_registry_audit SET action = 'revoked' \
         WHERE instance_id = $1::text::uuid",
        &[&id],
    );
    assert!(
        mutation.is_err(),
        "append-only audit rows must reject updates"
    );

    let private_columns: i64 = client
        .query_one(
            "SELECT count(*) FROM information_schema.columns \
             WHERE table_name IN ('service_instances', 'service_instance_keys') \
               AND column_name LIKE '%private%'",
            &[],
        )
        .expect("registry schema should be inspectable")
        .get(0);
    assert_eq!(private_columns, 0, "registry must not store private keys");
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
