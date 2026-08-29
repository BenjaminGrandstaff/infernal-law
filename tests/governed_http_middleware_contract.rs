//! Goal: prove the HTTP middleware translates strict signed headers into the
//! ordered kernel gate and returns only sanitized failures to callers.

use std::collections::HashSet;
use std::sync::Mutex;

use infernal_law::http::{GovernedHttpRequest, authenticate_governed_request};
use infernal_law::kernel::admission::AdmissionError;
use infernal_law::kernel::identity::ActorId;
use infernal_law::kernel::instance_keys::{InstanceCredential, InstanceId};
use infernal_law::kernel::instance_registry::{InstanceRegistryError, RegisteredInstance};
use infernal_law::kernel::replay_protection::{ReplayDisposition, ReplayProtectionError};
use infernal_law::kernel::request_gate::{
    CommunicationAdmissionCheck, ReplayReservation, ServiceRequestGate,
};
use infernal_law::kernel::service_requests::{
    EligibleInstanceResolver, ServiceRequestParts, ServiceRequestVerifier, SignedServiceRequest,
    VerifiedServiceRequest,
};
use uuid::Uuid;

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

#[derive(Default)]
struct ConsumeNonce(Mutex<HashSet<[u8; 32]>>);

impl ReplayReservation for ConsumeNonce {
    fn reserve_replay(
        &self,
        request: VerifiedServiceRequest,
        _: i64,
    ) -> Result<ReplayDisposition, ReplayProtectionError> {
        if self.0.lock().unwrap().insert(request.nonce_digest()) {
            Ok(ReplayDisposition::Fresh)
        } else {
            Err(ReplayProtectionError::ReplayDetected)
        }
    }
}

struct Admission {
    service_id: ActorId,
    enabled: bool,
}

impl CommunicationAdmissionCheck for Admission {
    fn require_communication(&self, service_id: ActorId) -> Result<i64, AdmissionError> {
        if service_id != self.service_id {
            return Err(AdmissionError::UnknownService(service_id));
        }
        if !self.enabled {
            return Err(AdmissionError::Disabled(service_id));
        }
        Ok(4)
    }
}

fn fixture(
    enabled: bool,
) -> (
    InstanceCredential,
    ServiceRequestGate<ServiceRequestVerifier<KnownInstance>, ConsumeNonce, Admission>,
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
    let gate = ServiceRequestGate::new(
        ServiceRequestVerifier::new(KnownInstance(instance)),
        ConsumeNonce::default(),
        Admission {
            service_id: credential.public_key().service_id(),
            enabled,
        },
    );
    let parts = ServiceRequestParts::new(
        "GET",
        "kernel.example.test",
        "/v1/subscriptions?active=true",
        "application/json",
        b"",
        Uuid::new_v4(),
    )
    .unwrap();
    let signed =
        SignedServiceRequest::sign(parts, &credential, 990, 1_020, "http_middleware_001").unwrap();
    (credential, gate, signed)
}

fn authenticate(
    signed: &SignedServiceRequest,
    gate: &impl infernal_law::http::GovernedRequestAuthenticator,
    body: &[u8],
) -> Result<infernal_law::kernel::request_gate::AdmittedServiceRequest, infernal_law::http::Response>
{
    let service_id = signed.service_id().to_string();
    let instance_id = signed.instance_id().to_string();
    let request_id = signed.parts().request_id().to_string();
    authenticate_governed_request(
        GovernedHttpRequest {
            method: "GET",
            authority: "kernel.example.test",
            path_and_query: "/v1/subscriptions?active=true",
            content_type: "application/json",
            body,
            service_id: &service_id,
            instance_id: &instance_id,
            request_id: &request_id,
            content_digest: signed.content_digest(),
            signature_input: signed.signature_input(),
            signature: signed.signature(),
        },
        gate,
        1_000,
    )
}

#[test]
fn valid_headers_reach_the_governed_boundary_with_typed_context() {
    let (credential, gate, signed) = fixture(true);

    let admitted = authenticate(&signed, &gate, b"").unwrap();

    assert_eq!(
        admitted.verified().service_id(),
        credential.public_key().service_id()
    );
    assert_eq!(admitted.replay_disposition(), ReplayDisposition::Fresh);
    assert_eq!(admitted.admission_revision(), 4);
}

#[test]
fn exact_http_replay_is_rejected_before_a_handler_can_run() {
    let (_, gate, signed) = fixture(true);

    authenticate(&signed, &gate, b"").unwrap();
    let response = authenticate(&signed, &gate, b"").unwrap_err();

    assert_eq!(response.status, "401 Unauthorized");
    assert!(response.body.contains("request_rejected"));
    assert!(!response.body.contains("nonce"));
}

#[test]
fn disabled_communication_returns_a_sanitized_deterministic_response() {
    let (_, gate, signed) = fixture(false);

    let response = authenticate(&signed, &gate, b"").unwrap_err();

    assert_eq!(response.status, "403 Forbidden");
    assert!(response.body.contains("communication_disabled"));
    assert!(!response.body.contains(&signed.service_id().to_string()));
}

#[test]
fn tampered_content_returns_no_signature_or_registry_details() {
    let (_, gate, signed) = fixture(true);

    let response = authenticate(&signed, &gate, b"tampered").unwrap_err();

    assert_eq!(response.status, "401 Unauthorized");
    assert!(!response.body.contains("digest"));
    assert!(!response.body.contains("signature"));
    assert!(!response.body.contains(&signed.instance_id().to_string()));
}
