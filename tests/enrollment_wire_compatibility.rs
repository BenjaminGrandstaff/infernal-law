//! Goal: prove infernal-client-rs's `EnrollmentSubmission` produces exactly
//! the signed proof infernal-law's own `EnrollmentService` accepts. This is
//! the same dogfooding check as `infernal_client_rs_wire_compatibility.rs`,
//! extended to ADR-0008: infernal-client-rs never links kernel code, so it
//! reimplements the proof message layout independently
//! (`kernel::enrollment::proof_message` on this side) -- if either side
//! drifts, this test is what catches it, not a shared implementation.

use std::sync::{Arc, Mutex};

use infernal_client::{ClientCredential, EnrollmentSubmission};
use infernal_law::http::enrollment_dto::EnrollmentSubmissionRequest;
use infernal_law::kernel::enrollment::{
    ENROLLMENT_AUDIENCE, EnrollmentBinding, EnrollmentBindingRepository, EnrollmentChallenge,
    EnrollmentError, EnrollmentService, VerifiedWorkload, WorkloadTokenReviewer,
};
use infernal_law::kernel::identity::ActorId;
use infernal_law::kernel::instance_keys::InstanceId;
use infernal_law::kernel::instance_registry::{
    InstanceRegistryError, InstanceRegistryRepository, InstanceRegistryService, LeasePolicy,
    RegisteredInstance,
};

const BOUND_TOKEN: &str = "bound-workload-token";
const POD_UID: &str = "pod-uid";
const NAMESPACE: &str = "workers";
const SERVICE_ACCOUNT: &str = "indexer";
const SERVICE_ACCOUNT_UID: &str = "service-account-uid";

#[derive(Clone)]
struct FakeReviewer;

impl WorkloadTokenReviewer for FakeReviewer {
    fn review(&self, token: &str, audience: &str) -> Result<VerifiedWorkload, EnrollmentError> {
        if token != BOUND_TOKEN || audience != ENROLLMENT_AUDIENCE {
            return Err(EnrollmentError::TokenRejected);
        }
        VerifiedWorkload::new(
            NAMESPACE,
            SERVICE_ACCOUNT,
            SERVICE_ACCOUNT_UID,
            "indexer-1",
            POD_UID,
            vec![ENROLLMENT_AUDIENCE.to_owned()],
        )
        .map_err(|_| EnrollmentError::TokenRejected)
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

    fn set_enabled(&self, _: ActorId, _: bool) -> Result<(), EnrollmentError> {
        unreachable!()
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
struct FakeRegistry(Arc<Mutex<Vec<RegisteredInstance>>>);

impl InstanceRegistryRepository for FakeRegistry {
    fn insert(&self, instance: RegisteredInstance) -> Result<(), InstanceRegistryError> {
        self.0.lock().unwrap().push(instance);
        Ok(())
    }

    fn find(&self, _: InstanceId) -> Result<Option<RegisteredInstance>, InstanceRegistryError> {
        unreachable!()
    }

    fn renew(
        &self,
        _: InstanceId,
        _: i64,
        _: i64,
        _: i64,
    ) -> Result<RegisteredInstance, InstanceRegistryError> {
        unreachable!()
    }

    fn revoke(&self, _: InstanceId, _: i64) -> Result<RegisteredInstance, InstanceRegistryError> {
        unreachable!()
    }
}

#[test]
fn a_client_built_submission_verifies_and_registers_against_the_real_kernel_service() {
    let service_id = ActorId::new();
    let credential = ClientCredential::generate(*service_id.as_uuid());
    let bindings = FakeBindings::default();
    bindings.0.lock().unwrap().push(
        EnrollmentBinding::restore(
            service_id,
            NAMESPACE,
            SERVICE_ACCOUNT,
            SERVICE_ACCOUNT_UID,
            true,
        )
        .unwrap(),
    );
    let service = EnrollmentService::new(
        FakeReviewer,
        bindings,
        InstanceRegistryService::new(FakeRegistry::default(), LeasePolicy::new(60).unwrap()),
    );
    let challenge = service.issue_challenge(service_id, 1_000).unwrap();

    // The candidate's side: infernal-client-rs builds and signs the proof
    // with no knowledge of the kernel's own types.
    let submission = EnrollmentSubmission::sign(
        &credential,
        *challenge.as_bytes(),
        "https://indexer.workers.svc:8443",
        POD_UID,
        BOUND_TOKEN.to_owned(),
    )
    .unwrap();
    let wire_bytes = serde_json::to_vec(&submission).unwrap();

    // The kernel's side: parse the exact bytes a real HTTP body would
    // carry, using the kernel's own DTO and domain types -- no shortcut
    // through infernal-client-rs's types.
    let submission_request: EnrollmentSubmissionRequest =
        serde_json::from_slice(&wire_bytes).unwrap();
    let enrollment_request = submission_request.into_domain().unwrap();

    let registered = service
        .authenticate_and_register(enrollment_request, 1_005)
        .unwrap();

    assert_eq!(registered.public_key().service_id(), service_id);
    assert_eq!(registered.endpoint(), "https://indexer.workers.svc:8443");
}

#[test]
fn a_tampered_pod_uid_fails_verification_even_though_it_still_parses() {
    let service_id = ActorId::new();
    let credential = ClientCredential::generate(*service_id.as_uuid());
    let bindings = FakeBindings::default();
    bindings.0.lock().unwrap().push(
        EnrollmentBinding::restore(
            service_id,
            NAMESPACE,
            SERVICE_ACCOUNT,
            SERVICE_ACCOUNT_UID,
            true,
        )
        .unwrap(),
    );
    let service = EnrollmentService::new(
        FakeReviewer,
        bindings,
        InstanceRegistryService::new(FakeRegistry::default(), LeasePolicy::new(60).unwrap()),
    );
    let challenge = service.issue_challenge(service_id, 2_000).unwrap();

    let submission = EnrollmentSubmission::sign(
        &credential,
        *challenge.as_bytes(),
        "https://indexer.workers.svc:8443",
        POD_UID,
        BOUND_TOKEN.to_owned(),
    )
    .unwrap();
    let mut wire_value: serde_json::Value = serde_json::to_value(&submission).unwrap();
    wire_value["pod_uid"] = serde_json::Value::String("someone-elses-pod".to_owned());
    let submission_request: EnrollmentSubmissionRequest =
        serde_json::from_value(wire_value).unwrap();
    let enrollment_request = submission_request.into_domain().unwrap();

    assert_eq!(
        service.authenticate_and_register(enrollment_request, 2_005),
        Err(EnrollmentError::InvalidProof)
    );
}
