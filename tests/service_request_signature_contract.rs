//! Goal: prove signed service requests authenticate every security-relevant
//! HTTP component and fail closed when request data or signature metadata changes.

use infernal_law::kernel::identity::ActorId;
use infernal_law::kernel::instance_keys::{InstanceCredential, InstanceId};
use infernal_law::kernel::instance_registry::{InstanceRegistryError, RegisteredInstance};
use infernal_law::kernel::service_requests::{
    EligibleInstanceResolver, ServiceRequestAuthenticationError, ServiceRequestParts,
    ServiceRequestVerifier, SignedServiceRequest,
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

fn fixture() -> (
    InstanceCredential,
    ServiceRequestVerifier<KnownInstance>,
    ServiceRequestParts,
) {
    let credential = InstanceCredential::generate(ActorId::new());
    let registered = RegisteredInstance::create(
        credential.public_key().clone(),
        "https://worker.example.test",
        900,
        1_100,
    )
    .unwrap();
    let parts = ServiceRequestParts::new(
        "POST",
        "kernel.example.test",
        "/v1/subscriptions?source=worker",
        "application/json",
        br#"{"event_type":"resource.created.v1"}"#,
        Uuid::new_v4(),
    )
    .unwrap();
    (
        credential,
        ServiceRequestVerifier::new(KnownInstance(registered)),
        parts,
    )
}

#[test]
fn valid_signature_returns_stable_authenticated_context() {
    let (credential, verifier, parts) = fixture();
    let request =
        SignedServiceRequest::sign(parts.clone(), &credential, 990, 1_020, "unique_nonce_0001")
            .unwrap();

    let verified = verifier.verify(&request, 1_000).unwrap();

    assert_eq!(verified.service_id(), credential.public_key().service_id());
    assert_eq!(
        verified.instance_id(),
        credential.public_key().instance_id()
    );
    assert_eq!(verified.key_id(), credential.public_key().key_id());
    assert_eq!(verified.request_id(), parts.request_id());
    assert_eq!(verified.created(), 990);
    assert_eq!(verified.expires(), 1_020);
}

#[test]
fn changing_a_covered_http_component_invalidates_the_signature() {
    let (credential, verifier, parts) = fixture();
    let signed =
        SignedServiceRequest::sign(parts, &credential, 990, 1_020, "unique_nonce_0002").unwrap();
    let changed_parts = ServiceRequestParts::new(
        "DELETE",
        "kernel.example.test",
        "/v1/subscriptions?source=worker",
        "application/json",
        signed.parts().body(),
        signed.parts().request_id(),
    )
    .unwrap();
    let changed = SignedServiceRequest::from_wire(
        changed_parts,
        &signed.service_id().to_string(),
        &signed.instance_id().to_string(),
        signed.content_digest(),
        signed.signature_input(),
        signed.signature(),
    )
    .unwrap();

    assert_eq!(
        verifier.verify(&changed, 1_000),
        Err(ServiceRequestAuthenticationError::InvalidSignature)
    );
}

#[test]
fn changing_the_body_fails_content_digest_verification() {
    let (credential, verifier, parts) = fixture();
    let signed =
        SignedServiceRequest::sign(parts, &credential, 990, 1_020, "unique_nonce_0003").unwrap();
    let changed_parts = ServiceRequestParts::new(
        signed.parts().method(),
        "kernel.example.test",
        "/v1/subscriptions?source=worker",
        signed.parts().content_type(),
        b"{}",
        signed.parts().request_id(),
    )
    .unwrap();
    let changed = SignedServiceRequest::from_wire(
        changed_parts,
        &signed.service_id().to_string(),
        &signed.instance_id().to_string(),
        signed.content_digest(),
        signed.signature_input(),
        signed.signature(),
    )
    .unwrap();

    assert_eq!(
        verifier.verify(&changed, 1_000),
        Err(ServiceRequestAuthenticationError::InvalidContentDigest)
    );
}

#[test]
fn stale_and_far_future_signatures_are_rejected() {
    let (credential, verifier, parts) = fixture();
    let stale =
        SignedServiceRequest::sign(parts.clone(), &credential, 950, 980, "unique_nonce_0004")
            .unwrap();
    let future =
        SignedServiceRequest::sign(parts, &credential, 1_010, 1_040, "unique_nonce_0005").unwrap();

    assert_eq!(
        verifier.verify(&stale, 1_000),
        Err(ServiceRequestAuthenticationError::NotFresh)
    );
    assert_eq!(
        verifier.verify(&future, 1_000),
        Err(ServiceRequestAuthenticationError::NotFresh)
    );
}

#[test]
fn another_instances_key_cannot_sign_for_the_registered_instance() {
    let (credential, verifier, parts) = fixture();
    let impostor = InstanceCredential::generate(credential.public_key().service_id());
    let signed =
        SignedServiceRequest::sign(parts, &impostor, 990, 1_020, "unique_nonce_0006").unwrap();

    assert!(matches!(
        verifier.verify(&signed, 1_000),
        Err(ServiceRequestAuthenticationError::Registry(
            InstanceRegistryError::NotFound(_)
        ))
    ));
}

#[test]
fn malformed_or_extended_signature_profiles_are_rejected() {
    let (credential, verifier, parts) = fixture();
    let signed =
        SignedServiceRequest::sign(parts, &credential, 990, 1_020, "unique_nonce_0008").unwrap();
    let extended_input = format!("{};unexpected=1", signed.signature_input());
    let changed = SignedServiceRequest::from_wire(
        signed.parts().clone(),
        &signed.service_id().to_string(),
        &signed.instance_id().to_string(),
        signed.content_digest(),
        &extended_input,
        signed.signature(),
    )
    .unwrap();

    assert_eq!(
        verifier.verify(&changed, 1_000),
        Err(ServiceRequestAuthenticationError::Malformed)
    );
}

#[test]
fn debug_output_does_not_disclose_the_signature() {
    let (credential, _, parts) = fixture();
    let signed =
        SignedServiceRequest::sign(parts, &credential, 990, 1_020, "unique_nonce_0007").unwrap();

    let output = format!("{signed:?}");

    assert!(output.contains("[redacted]"));
    assert!(!output.contains("resource.created.v1"));
    assert!(!output.contains(signed.signature()));
}
