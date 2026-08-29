//! Goal: prove governed requests pass signature, replay, and communication
//! admission checks in that exact order and fail closed at each boundary.

use std::sync::{Arc, Mutex};

use infernal_law::kernel::admission::AdmissionError;
use infernal_law::kernel::identity::ActorId;
use infernal_law::kernel::instance_keys::{InstanceCredential, InstanceId};
use infernal_law::kernel::instance_registry::{InstanceRegistryError, RegisteredInstance};
use infernal_law::kernel::replay_protection::{ReplayDisposition, ReplayProtectionError};
use infernal_law::kernel::request_gate::{
    CommunicationAdmissionCheck, ReplayReservation, ServiceRequestGate, ServiceRequestGateError,
    SignatureVerification,
};
use infernal_law::kernel::service_requests::{
    EligibleInstanceResolver, ServiceRequestAuthenticationError, ServiceRequestParts,
    ServiceRequestVerifier, SignedServiceRequest, VerifiedServiceRequest,
};
use uuid::Uuid;

type Calls = Arc<Mutex<Vec<&'static str>>>;

#[derive(Clone)]
struct KnownInstance(RegisteredInstance);

impl EligibleInstanceResolver for KnownInstance {
    fn find_eligible(
        &self,
        instance_id: InstanceId,
        now: i64,
    ) -> Result<RegisteredInstance, InstanceRegistryError> {
        if self.0.public_key().instance_id() != instance_id {
            return Err(InstanceRegistryError::NotFound(instance_id));
        }
        if !self.0.is_eligible_at(now) {
            return Err(InstanceRegistryError::Expired(instance_id));
        }
        Ok(self.0.clone())
    }
}

struct RecordingSignatures {
    verifier: ServiceRequestVerifier<KnownInstance>,
    calls: Calls,
}

impl SignatureVerification for RecordingSignatures {
    fn verify_signature(
        &self,
        request: &SignedServiceRequest,
        now: i64,
    ) -> Result<VerifiedServiceRequest, ServiceRequestAuthenticationError> {
        self.calls.lock().unwrap().push("signature");
        self.verifier.verify(request, now)
    }
}

struct RecordingReplay {
    calls: Calls,
    result: Result<ReplayDisposition, ReplayProtectionError>,
}

impl ReplayReservation for RecordingReplay {
    fn reserve_replay(
        &self,
        _: VerifiedServiceRequest,
        _: i64,
    ) -> Result<ReplayDisposition, ReplayProtectionError> {
        self.calls.lock().unwrap().push("replay");
        self.result.clone()
    }
}

struct RecordingAdmission {
    calls: Calls,
    result: Result<i64, AdmissionError>,
}

impl CommunicationAdmissionCheck for RecordingAdmission {
    fn require_communication(&self, _: ActorId) -> Result<i64, AdmissionError> {
        self.calls.lock().unwrap().push("admission");
        self.result.clone()
    }
}

fn fixture() -> (
    InstanceCredential,
    ServiceRequestVerifier<KnownInstance>,
    SignedServiceRequest,
) {
    let credential = InstanceCredential::generate(ActorId::new());
    let instance = RegisteredInstance::create(
        credential.public_key().clone(),
        "https://worker.example.test",
        900,
        1_100,
    )
    .unwrap();
    let verifier = ServiceRequestVerifier::new(KnownInstance(instance));
    let parts = ServiceRequestParts::new(
        "GET",
        "kernel.example.test",
        "/v1/subscriptions",
        "application/json",
        b"",
        Uuid::new_v4(),
    )
    .unwrap();
    let signed =
        SignedServiceRequest::sign(parts, &credential, 990, 1_020, "middleware_nonce_01").unwrap();
    (credential, verifier, signed)
}

#[test]
fn successful_gate_returns_only_after_all_checks_in_order() {
    let (credential, verifier, signed) = fixture();
    let calls = Calls::default();
    let gate = ServiceRequestGate::new(
        RecordingSignatures {
            verifier,
            calls: calls.clone(),
        },
        RecordingReplay {
            calls: calls.clone(),
            result: Ok(ReplayDisposition::Fresh),
        },
        RecordingAdmission {
            calls: calls.clone(),
            result: Ok(7),
        },
    );

    let admitted = gate.admit(&signed, 1_000).unwrap();

    assert_eq!(*calls.lock().unwrap(), ["signature", "replay", "admission"]);
    assert_eq!(
        admitted.verified().service_id(),
        credential.public_key().service_id()
    );
    assert_eq!(admitted.replay_disposition(), ReplayDisposition::Fresh);
    assert_eq!(admitted.admission_revision(), 7);
}

#[test]
fn replay_failure_prevents_the_admission_lookup() {
    let (_, verifier, signed) = fixture();
    let calls = Calls::default();
    let gate = ServiceRequestGate::new(
        RecordingSignatures {
            verifier,
            calls: calls.clone(),
        },
        RecordingReplay {
            calls: calls.clone(),
            result: Err(ReplayProtectionError::ReplayDetected),
        },
        RecordingAdmission {
            calls: calls.clone(),
            result: Ok(1),
        },
    );

    assert_eq!(
        gate.admit(&signed, 1_000),
        Err(ServiceRequestGateError::Replay(
            ReplayProtectionError::ReplayDetected
        ))
    );
    assert_eq!(*calls.lock().unwrap(), ["signature", "replay"]);
}

#[test]
fn disabled_admission_rejects_only_after_the_nonce_is_reserved() {
    let (credential, verifier, signed) = fixture();
    let service_id = credential.public_key().service_id();
    let calls = Calls::default();
    let gate = ServiceRequestGate::new(
        RecordingSignatures {
            verifier,
            calls: calls.clone(),
        },
        RecordingReplay {
            calls: calls.clone(),
            result: Ok(ReplayDisposition::Fresh),
        },
        RecordingAdmission {
            calls: calls.clone(),
            result: Err(AdmissionError::Disabled(service_id)),
        },
    );

    assert_eq!(
        gate.admit(&signed, 1_000),
        Err(ServiceRequestGateError::Admission(
            AdmissionError::Disabled(service_id)
        ))
    );
    assert_eq!(*calls.lock().unwrap(), ["signature", "replay", "admission"]);
}
