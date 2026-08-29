//! Goal: prove initial enrollment succeeds only when workload identity,
//! audience, Pod binding, service mapping, and key possession all agree.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use infernal_law::kernel::enrollment::{
    ENROLLMENT_AUDIENCE, EnrollmentBinding, EnrollmentBindingRepository, EnrollmentChallenge,
    EnrollmentError, EnrollmentRequest, EnrollmentService, VerifiedWorkload, WorkloadTokenReviewer,
};
use infernal_law::kernel::identity::ActorId;
use infernal_law::kernel::instance_keys::InstanceCredential;
use infernal_law::kernel::instance_registry::{
    InstanceRegistryError, InstanceRegistryRepository, InstanceRegistryService, LeasePolicy,
    RegisteredInstance,
};

#[derive(Clone)]
struct FakeReviewer {
    workload: VerifiedWorkload,
}

impl WorkloadTokenReviewer for FakeReviewer {
    fn review(&self, token: &str, audience: &str) -> Result<VerifiedWorkload, EnrollmentError> {
        if token != "bound-token" || audience != ENROLLMENT_AUDIENCE {
            return Err(EnrollmentError::TokenRejected);
        }
        Ok(self.workload.clone())
    }
}

#[derive(Clone, Default)]
struct FakeBindings(Arc<Mutex<Vec<EnrollmentBinding>>>);

static CHALLENGES: Mutex<Vec<(ActorId, EnrollmentChallenge, i64, bool)>> = Mutex::new(Vec::new());

impl EnrollmentBindingRepository for FakeBindings {
    fn insert_disabled(&self, binding: EnrollmentBinding) -> Result<(), EnrollmentError> {
        self.0.lock().unwrap().push(binding);
        Ok(())
    }

    fn set_enabled(&self, service_id: ActorId, enabled: bool) -> Result<(), EnrollmentError> {
        let mut values = self.0.lock().unwrap();
        let binding = values
            .iter_mut()
            .find(|value| value.service_id() == service_id)
            .ok_or(EnrollmentError::BindingNotFound)?;
        *binding = EnrollmentBinding::restore(
            binding.service_id(),
            binding.namespace(),
            binding.service_account(),
            binding.service_account_uid(),
            enabled,
        )?;
        Ok(())
    }

    fn find_workload(
        &self,
        namespace: &str,
        service_account: &str,
        service_account_uid: &str,
    ) -> Result<Option<EnrollmentBinding>, EnrollmentError> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .iter()
            .find(|value| {
                value.namespace() == namespace
                    && value.service_account() == service_account
                    && value.service_account_uid() == service_account_uid
            })
            .cloned())
    }

    fn insert_challenge(
        &self,
        service_id: ActorId,
        challenge: EnrollmentChallenge,
        expires_at: i64,
    ) -> Result<(), EnrollmentError> {
        CHALLENGES
            .lock()
            .unwrap()
            .push((service_id, challenge, expires_at, false));
        Ok(())
    }

    fn consume_challenge(
        &self,
        service_id: ActorId,
        challenge: EnrollmentChallenge,
        now: i64,
    ) -> Result<(), EnrollmentError> {
        let mut challenges = CHALLENGES.lock().unwrap();
        let value = challenges
            .iter_mut()
            .find(|value| {
                value.0 == service_id && value.1 == challenge && value.2 > now && !value.3
            })
            .ok_or(EnrollmentError::ChallengeRejected)?;
        value.3 = true;
        Ok(())
    }
}

#[derive(Clone, Default)]
struct FakeRegistry(Arc<Mutex<HashMap<String, RegisteredInstance>>>);

impl InstanceRegistryRepository for FakeRegistry {
    fn insert(&self, instance: RegisteredInstance) -> Result<(), InstanceRegistryError> {
        self.0
            .lock()
            .unwrap()
            .insert(instance.public_key().instance_id().to_string(), instance);
        Ok(())
    }

    fn find(
        &self,
        id: infernal_law::kernel::instance_keys::InstanceId,
    ) -> Result<Option<RegisteredInstance>, InstanceRegistryError> {
        Ok(self.0.lock().unwrap().get(&id.to_string()).cloned())
    }

    fn renew(
        &self,
        _: infernal_law::kernel::instance_keys::InstanceId,
        _: i64,
        _: i64,
        _: i64,
    ) -> Result<RegisteredInstance, InstanceRegistryError> {
        unreachable!()
    }

    fn revoke(
        &self,
        _: infernal_law::kernel::instance_keys::InstanceId,
        _: i64,
    ) -> Result<RegisteredInstance, InstanceRegistryError> {
        unreachable!()
    }
}

fn workload(audiences: Vec<String>, pod_uid: &str) -> VerifiedWorkload {
    VerifiedWorkload::new(
        "workers",
        "indexer",
        "service-account-uid",
        "indexer-1",
        pod_uid,
        audiences,
    )
    .unwrap()
}

fn service(
    service_id: ActorId,
    reviewer: FakeReviewer,
    enabled: bool,
) -> EnrollmentService<FakeReviewer, FakeBindings, FakeRegistry> {
    let bindings = FakeBindings::default();
    bindings.0.lock().unwrap().push(
        EnrollmentBinding::restore(
            service_id,
            "workers",
            "indexer",
            "service-account-uid",
            enabled,
        )
        .unwrap(),
    );
    EnrollmentService::new(
        reviewer,
        bindings,
        InstanceRegistryService::new(FakeRegistry::default(), LeasePolicy::new(60).unwrap()),
    )
}

fn request(
    credential: &InstanceCredential,
    challenge: EnrollmentChallenge,
    token: &str,
    pod_uid: &str,
) -> EnrollmentRequest {
    EnrollmentRequest::sign(
        credential,
        challenge,
        "https://indexer.workers.svc:8443",
        pod_uid,
        token.to_owned(),
    )
    .unwrap()
}

#[test]
fn verified_bound_workload_can_register_its_ephemeral_public_key() {
    let service_id = ActorId::new();
    let credential = InstanceCredential::generate(service_id);
    let enrollment = service(
        service_id,
        FakeReviewer {
            workload: workload(vec![ENROLLMENT_AUDIENCE.to_owned()], "pod-uid"),
        },
        true,
    );
    let challenge = enrollment.issue_challenge(service_id, 990).unwrap();

    let registered = enrollment
        .authenticate_and_register(
            request(&credential, challenge, "bound-token", "pod-uid"),
            1_000,
        )
        .unwrap();

    assert_eq!(registered.public_key(), credential.public_key());
    assert_eq!(registered.lease_expires_at(), 1_060);
}

#[test]
fn disabled_binding_fails_closed() {
    let service_id = ActorId::new();
    let credential = InstanceCredential::generate(service_id);
    let enrollment = service(
        service_id,
        FakeReviewer {
            workload: workload(vec![ENROLLMENT_AUDIENCE.to_owned()], "pod-uid"),
        },
        false,
    );
    let challenge = enrollment.issue_challenge(service_id, 990).unwrap();

    assert_eq!(
        enrollment.authenticate_and_register(
            request(&credential, challenge, "bound-token", "pod-uid"),
            1_000
        ),
        Err(EnrollmentError::BindingDisabled)
    );
}

#[test]
fn token_review_must_return_the_exact_audience() {
    let service_id = ActorId::new();
    let credential = InstanceCredential::generate(service_id);
    let enrollment = service(
        service_id,
        FakeReviewer {
            workload: workload(vec!["some-other-audience".to_owned()], "pod-uid"),
        },
        true,
    );
    let challenge = enrollment.issue_challenge(service_id, 990).unwrap();

    assert_eq!(
        enrollment.authenticate_and_register(
            request(&credential, challenge, "bound-token", "pod-uid"),
            1_000
        ),
        Err(EnrollmentError::AudienceMismatch)
    );
}

#[test]
fn signed_pod_uid_must_match_token_review() {
    let service_id = ActorId::new();
    let credential = InstanceCredential::generate(service_id);
    let enrollment = service(
        service_id,
        FakeReviewer {
            workload: workload(vec![ENROLLMENT_AUDIENCE.to_owned()], "different-pod"),
        },
        true,
    );
    let challenge = enrollment.issue_challenge(service_id, 990).unwrap();

    assert_eq!(
        enrollment.authenticate_and_register(
            request(&credential, challenge, "bound-token", "pod-uid"),
            1_000
        ),
        Err(EnrollmentError::PodMismatch)
    );
}

#[test]
fn workload_cannot_enroll_as_an_unbound_service() {
    let bound_service = ActorId::new();
    let credential = InstanceCredential::generate(ActorId::new());
    let enrollment = service(
        bound_service,
        FakeReviewer {
            workload: workload(vec![ENROLLMENT_AUDIENCE.to_owned()], "pod-uid"),
        },
        true,
    );
    let challenge = enrollment
        .issue_challenge(credential.public_key().service_id(), 990)
        .unwrap();

    assert_eq!(
        enrollment.authenticate_and_register(
            request(&credential, challenge, "bound-token", "pod-uid"),
            1_000
        ),
        Err(EnrollmentError::ServiceMismatch)
    );
}

#[test]
fn bearer_token_is_never_exposed_by_an_error() {
    let service_id = ActorId::new();
    let credential = InstanceCredential::generate(service_id);
    let enrollment = service(
        service_id,
        FakeReviewer {
            workload: workload(vec![ENROLLMENT_AUDIENCE.to_owned()], "pod-uid"),
        },
        true,
    );
    let challenge = enrollment.issue_challenge(service_id, 990).unwrap();
    let error = enrollment
        .authenticate_and_register(
            request(&credential, challenge, "rejected-secret", "pod-uid"),
            1_000,
        )
        .unwrap_err();

    assert!(!format!("{error:?} {error}").contains("rejected-secret"));
}

#[test]
fn challenge_can_be_consumed_only_once() {
    let service_id = ActorId::new();
    let credential = InstanceCredential::generate(service_id);
    let enrollment = service(
        service_id,
        FakeReviewer {
            workload: workload(vec![ENROLLMENT_AUDIENCE.to_owned()], "pod-uid"),
        },
        true,
    );
    let challenge = enrollment.issue_challenge(service_id, 990).unwrap();

    enrollment
        .authenticate_and_register(
            request(&credential, challenge, "bound-token", "pod-uid"),
            1_000,
        )
        .unwrap();
    assert_eq!(
        enrollment.authenticate_and_register(
            request(&credential, challenge, "bound-token", "pod-uid"),
            1_001,
        ),
        Err(EnrollmentError::ChallengeRejected)
    );
}
