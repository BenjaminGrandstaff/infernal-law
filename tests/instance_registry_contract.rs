//! Goal: verify public-key registration and lease behavior independently of
//! PostgreSQL and HTTP enrollment authentication.

use std::collections::HashMap;
use std::sync::Mutex;

use infernal_law::kernel::identity::ActorId;
use infernal_law::kernel::instance_keys::{InstanceCredential, InstanceId};
use infernal_law::kernel::instance_registry::{
    InstanceRegistryError, InstanceRegistryRepository, InstanceRegistryService, LeasePolicy,
    RegisteredInstance,
};

#[derive(Default)]
struct TestInstanceRegistry {
    instances: Mutex<HashMap<InstanceId, RegisteredInstance>>,
}

impl InstanceRegistryRepository for TestInstanceRegistry {
    fn insert(&self, instance: RegisteredInstance) -> Result<(), InstanceRegistryError> {
        let mut instances = self.instances.lock().unwrap();
        let id = instance.public_key().instance_id();
        if instances.contains_key(&id) {
            return Err(InstanceRegistryError::AlreadyExists(id));
        }
        instances.insert(id, instance);
        Ok(())
    }

    fn find(
        &self,
        instance_id: InstanceId,
    ) -> Result<Option<RegisteredInstance>, InstanceRegistryError> {
        Ok(self.instances.lock().unwrap().get(&instance_id).cloned())
    }

    fn renew(
        &self,
        instance_id: InstanceId,
        expected_revision: i64,
        renewed_at: i64,
        lease_expires_at: i64,
    ) -> Result<RegisteredInstance, InstanceRegistryError> {
        let mut instances = self.instances.lock().unwrap();
        let current = instances
            .get(&instance_id)
            .cloned()
            .ok_or(InstanceRegistryError::NotFound(instance_id))?;
        if current.revoked_at().is_some() {
            return Err(InstanceRegistryError::Revoked(instance_id));
        }
        if current.registered_at() > renewed_at {
            return Err(InstanceRegistryError::InvalidTimestamp);
        }
        if current.lease_expires_at() <= renewed_at {
            return Err(InstanceRegistryError::Expired(instance_id));
        }
        if current.lease_revision() != expected_revision {
            return Err(InstanceRegistryError::RevisionConflict(instance_id));
        }
        let renewed = RegisteredInstance::restore(
            current.public_key().clone(),
            current.endpoint(),
            current.registered_at(),
            lease_expires_at,
            current.lease_revision() + 1,
            None,
        )?;
        instances.insert(instance_id, renewed.clone());
        Ok(renewed)
    }

    fn revoke(
        &self,
        instance_id: InstanceId,
        revoked_at: i64,
    ) -> Result<RegisteredInstance, InstanceRegistryError> {
        let mut instances = self.instances.lock().unwrap();
        let current = instances
            .get(&instance_id)
            .cloned()
            .ok_or(InstanceRegistryError::NotFound(instance_id))?;
        if current.revoked_at().is_some() {
            return Err(InstanceRegistryError::Revoked(instance_id));
        }
        if current.registered_at() > revoked_at {
            return Err(InstanceRegistryError::InvalidTimestamp);
        }
        let revoked = RegisteredInstance::restore(
            current.public_key().clone(),
            current.endpoint(),
            current.registered_at(),
            current.lease_expires_at(),
            current.lease_revision(),
            Some(revoked_at),
        )?;
        instances.insert(instance_id, revoked.clone());
        Ok(revoked)
    }
}

fn service() -> InstanceRegistryService<TestInstanceRegistry> {
    InstanceRegistryService::new(
        TestInstanceRegistry::default(),
        LeasePolicy::new(60).unwrap(),
    )
}

#[test]
fn verified_registration_creates_a_bounded_eligible_lease() {
    let service = service();
    let credential = InstanceCredential::generate(ActorId::new());
    let registered = service
        .register_verified(
            credential.public_key().clone(),
            "https://worker.example.test",
            1_000,
        )
        .unwrap();

    assert_eq!(registered.lease_revision(), 1);
    assert_eq!(registered.lease_expires_at(), 1_060);
    assert!(
        service
            .find_eligible(registered.public_key().instance_id(), 1_059)
            .is_ok()
    );
    assert_eq!(
        service.find_eligible(registered.public_key().instance_id(), 1_060),
        Err(InstanceRegistryError::Expired(
            registered.public_key().instance_id()
        ))
    );
}

#[test]
fn lease_renewal_is_compare_and_set_and_revocation_is_terminal() {
    let service = service();
    let credential = InstanceCredential::generate(ActorId::new());
    let registered = service
        .register_verified(
            credential.public_key().clone(),
            "https://worker.example.test",
            2_000,
        )
        .unwrap();
    let id = registered.public_key().instance_id();

    let renewed = service.renew(id, 1, 2_030).unwrap();
    assert_eq!(renewed.lease_revision(), 2);
    assert_eq!(renewed.lease_expires_at(), 2_090);
    assert_eq!(
        service.renew(id, 1, 2_040),
        Err(InstanceRegistryError::RevisionConflict(id))
    );

    let revoked = service.revoke(id, 2_041).unwrap();
    assert_eq!(revoked.revoked_at(), Some(2_041));
    assert_eq!(
        service.find_eligible(id, 2_042),
        Err(InstanceRegistryError::Revoked(id))
    );
    assert_eq!(
        service.renew(id, 2, 2_042),
        Err(InstanceRegistryError::Revoked(id))
    );
}

#[test]
fn invalid_endpoint_and_lease_configuration_fail_before_persistence() {
    assert_eq!(
        LeasePolicy::new(0),
        Err(InstanceRegistryError::InvalidLeaseDuration)
    );
    let service = service();
    let credential = InstanceCredential::generate(ActorId::new());
    assert_eq!(
        service.register_verified(credential.public_key().clone(), "http://worker", 3_000),
        Err(InstanceRegistryError::InvalidEndpoint)
    );
    assert_eq!(
        service.register_verified(
            InstanceCredential::generate(ActorId::new())
                .public_key()
                .clone(),
            "https://worker.example.test",
            -1,
        ),
        Err(InstanceRegistryError::InvalidTimestamp)
    );
}
