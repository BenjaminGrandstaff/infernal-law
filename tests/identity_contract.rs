//! Goal: verify ILK-001 through the identity module's public contract without
//! depending on PostgreSQL or private implementation details.

use std::collections::HashMap;
use std::sync::Mutex;

use infernal_law::kernel::identity::{
    ActorId, ActorKind, Identity, IdentityError, IdentityRepository, IdentityService,
    IdentityStatus,
};

#[derive(Default)]
struct TestIdentityRepository {
    identities: Mutex<HashMap<ActorId, Identity>>,
}

impl IdentityRepository for TestIdentityRepository {
    fn insert(&self, identity: Identity) -> Result<(), IdentityError> {
        let mut identities = self.identities.lock().unwrap();
        if identities.contains_key(&identity.id()) {
            return Err(IdentityError::AlreadyExists(identity.id()));
        }
        identities.insert(identity.id(), identity);
        Ok(())
    }

    fn find(&self, id: ActorId) -> Result<Option<Identity>, IdentityError> {
        Ok(self.identities.lock().unwrap().get(&id).cloned())
    }

    fn save(&self, identity: Identity) -> Result<(), IdentityError> {
        let mut identities = self.identities.lock().unwrap();
        if !identities.contains_key(&identity.id()) {
            return Err(IdentityError::NotFound(identity.id()));
        }
        identities.insert(identity.id(), identity);
        Ok(())
    }
}

#[test]
fn ilk_001_identity_lifecycle_preserves_id_and_enforces_status() {
    let service = IdentityService::new(TestIdentityRepository::default());
    let created = service
        .create(ActorKind::Worker, "Evidence worker")
        .unwrap();

    assert_eq!(created.status(), IdentityStatus::Active);
    assert_eq!(service.resolve_active(created.id()).unwrap(), created);

    let renamed = service.rename(created.id(), "Evidence worker v2").unwrap();
    assert_eq!(renamed.id(), created.id());
    assert_eq!(renamed.display_name(), "Evidence worker v2");

    let disabled = service.disable(created.id()).unwrap();
    assert_eq!(disabled.id(), created.id());
    assert_eq!(disabled.status(), IdentityStatus::Disabled);
    assert_eq!(
        service.resolve_active(created.id()).unwrap_err(),
        IdentityError::Disabled(created.id())
    );
}

#[test]
fn ilk_001_distinguishes_services_and_workers() {
    let service = IdentityService::new(TestIdentityRepository::default());

    let service_actor = service.create(ActorKind::Service, "Service").unwrap();
    let worker = service.create(ActorKind::Worker, "Worker").unwrap();

    assert_eq!(service_actor.kind(), ActorKind::Service);
    assert_eq!(worker.kind(), ActorKind::Worker);
}
