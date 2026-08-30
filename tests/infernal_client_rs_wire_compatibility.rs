//! Goal: prove infernal-client-rs produces exactly the signed request shape
//! infernal-law's own `ServiceRequestVerifier` accepts. This is the
//! dogfooding check behind depending on the reference client crate instead
//! of writing a second, bespoke signing implementation inside the kernel
//! (ADR-0012): if this ever drifts, this test is what catches it.

use infernal_client::{
    ClientCredential, ClientPublicKey, IncomingRequest, RequestParts as ClientRequestParts,
    SignedRequest, verify_incoming,
};
use infernal_law::kernel::identity::ActorId;
use infernal_law::kernel::instance_keys::{InstanceCredential, InstanceId, InstancePublicKey};
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

/// Generates an `infernal-client-rs` credential and mirrors its identity
/// into the kernel's own typed registry, exactly as the kernel's real
/// instance registry would hold it after that client enrolled.
fn fixture() -> (ClientCredential, ServiceRequestVerifier<KnownInstance>) {
    let credential = ClientCredential::generate(Uuid::new_v4());
    let public_key = credential.public_key();
    let kernel_public_key = InstancePublicKey::restore(
        ActorId::from_uuid(public_key.service_id()),
        public_key.instance_id().to_string().parse().unwrap(),
        public_key.key_id().to_string().parse().unwrap(),
        *public_key.public_key_bytes(),
    )
    .unwrap();
    let registered = RegisteredInstance::create(
        kernel_public_key,
        "https://evaluator.example.test",
        900,
        1_100,
    )
    .unwrap();
    (
        credential,
        ServiceRequestVerifier::new(KnownInstance(registered)),
    )
}

fn sign_with_client(
    credential: &ClientCredential,
    body: &[u8],
    request_id: Uuid,
    nonce: &str,
) -> SignedRequest {
    let parts = ClientRequestParts::new(
        "POST",
        "kernel.example.test",
        "/v1/subscriptions",
        "application/json",
        body,
        request_id,
    )
    .unwrap();
    SignedRequest::sign(parts, credential, 990, 1_020, nonce).unwrap()
}

/// Reconstructs the kernel's wire-level view exactly as an HTTP transport
/// would from a client's produced headers and body, proving the two sides
/// agree byte-for-byte rather than merely structurally.
fn as_kernel_request(
    signed: &SignedRequest,
    body: &[u8],
    request_id: Uuid,
) -> Result<SignedServiceRequest, ServiceRequestAuthenticationError> {
    let kernel_parts = ServiceRequestParts::new(
        "POST",
        "kernel.example.test",
        "/v1/subscriptions",
        "application/json",
        body,
        request_id,
    )
    .unwrap();
    SignedServiceRequest::from_wire(
        kernel_parts,
        &signed.service_id().to_string(),
        &signed.instance_id().to_string(),
        signed.content_digest(),
        signed.signature_input(),
        signed.signature(),
    )
}

#[test]
fn a_request_signed_by_infernal_client_rs_verifies_against_the_kernels_own_verifier() {
    let (credential, verifier) = fixture();
    let request_id = Uuid::new_v4();
    let body = br#"{"event_type":"resource.created.v1"}"#;
    let signed = sign_with_client(
        &credential,
        body,
        request_id,
        "infernal_client_rs_wire_0001",
    );

    let kernel_request = as_kernel_request(&signed, body, request_id).unwrap();
    let verified = verifier.verify(&kernel_request, 1_000).unwrap();

    assert_eq!(
        verified.service_id(),
        ActorId::from_uuid(credential.public_key().service_id())
    );
    assert_eq!(verified.request_id(), request_id);
    assert_eq!(verified.created(), 990);
    assert_eq!(verified.expires(), 1_020);
}

#[test]
fn a_body_altered_after_signing_fails_the_kernels_content_digest_check() {
    let (credential, verifier) = fixture();
    let request_id = Uuid::new_v4();
    let signed = sign_with_client(
        &credential,
        b"original body",
        request_id,
        "infernal_client_rs_wire_0002",
    );

    let kernel_request = as_kernel_request(&signed, b"tampered body", request_id).unwrap();

    assert_eq!(
        verifier.verify(&kernel_request, 1_000),
        Err(ServiceRequestAuthenticationError::InvalidContentDigest)
    );
}

/// Mirrors `HttpPolicyEvaluator::build_signed_request`'s exact signing path:
/// the kernel's own long-lived `InstanceCredential` signs via
/// `SignedRequest::sign_with`, restoring a `ClientPublicKey` from the same
/// bytes rather than generating a second key. This is the specific
/// verification mechanism a reference policy evaluator will run against
/// signed kernel calls, so it must be proven independently of the
/// kernel-signs/kernel-verifies round trip above.
#[test]
fn a_request_signed_by_the_kernels_own_instance_credential_verifies_via_infernal_client_rs() {
    let credential = InstanceCredential::generate(ActorId::new());
    let public_key = credential.public_key();
    let client_public_key = ClientPublicKey::restore(
        *public_key.service_id().as_uuid(),
        *public_key.instance_id().as_uuid(),
        *public_key.key_id().as_uuid(),
        *public_key.public_key_bytes(),
    )
    .unwrap();

    let request_id = Uuid::new_v4();
    let body = br#"{"action":"billing.invoice.submit"}"#;
    let parts = ClientRequestParts::new(
        "POST",
        "policy-evaluator.example.test",
        "/v1/authority/evaluate",
        "application/json",
        body,
        request_id,
    )
    .unwrap();
    let signed = SignedRequest::sign_with(
        parts,
        &client_public_key,
        990,
        1_020,
        "infernal_client_rs_wire_0004",
        |message| *credential.sign(message).as_bytes(),
    )
    .unwrap();

    let incoming = IncomingRequest::from_wire(
        signed.parts().clone(),
        &signed.service_id().to_string(),
        &signed.instance_id().to_string(),
        signed.content_digest(),
        signed.signature_input(),
        signed.signature(),
    )
    .unwrap();

    let verified = verify_incoming(&incoming, &client_public_key, 1_000).unwrap();

    assert_eq!(verified.service_id(), *public_key.service_id().as_uuid());
    assert_eq!(verified.request_id(), request_id);
    assert_eq!(verified.created(), 990);
    assert_eq!(verified.expires(), 1_020);
}

#[test]
fn a_request_from_an_unregistered_client_credential_is_rejected() {
    let (_registered_credential, verifier) = fixture();
    let impostor = ClientCredential::generate(Uuid::new_v4());
    let request_id = Uuid::new_v4();
    let body = b"{}";
    let signed = sign_with_client(&impostor, body, request_id, "infernal_client_rs_wire_0003");

    let kernel_request = as_kernel_request(&signed, body, request_id).unwrap();

    assert!(matches!(
        verifier.verify(&kernel_request, 1_000),
        Err(ServiceRequestAuthenticationError::Registry(_))
    ));
}
