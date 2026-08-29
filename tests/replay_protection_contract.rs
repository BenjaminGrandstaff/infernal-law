//! Goal: prove nonce consumption and request-ID binding are atomic while a
//! correctly re-signed retry remains available to the future idempotency layer.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::thread;

use infernal_law::kernel::identity::ActorId;
use infernal_law::kernel::instance_keys::{InstanceCredential, InstanceId, KeyId};
use infernal_law::kernel::instance_registry::{InstanceRegistryError, RegisteredInstance};
use infernal_law::kernel::replay_protection::{
    ReplayDisposition, ReplayProtectionError, ReplayProtectionRepository, ReplayProtectionService,
    ReplayReservation,
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
struct ReplayState {
    nonces: HashSet<(KeyId, [u8; 32])>,
    requests: HashMap<(ActorId, Uuid), [u8; 32]>,
}

#[derive(Clone, Default)]
struct MemoryReplayRepository(Arc<Mutex<ReplayState>>);

impl ReplayProtectionRepository for MemoryReplayRepository {
    fn reserve(
        &self,
        reservation: ReplayReservation,
    ) -> Result<ReplayDisposition, ReplayProtectionError> {
        let mut state = self.0.lock().unwrap();
        if !state
            .nonces
            .insert((reservation.key_id(), *reservation.nonce_digest()))
        {
            return Err(ReplayProtectionError::ReplayDetected);
        }

        let request_key = (reservation.service_id(), reservation.request_id());
        match state.requests.get(&request_key) {
            Some(fingerprint) if fingerprint == reservation.request_fingerprint() => {
                Ok(ReplayDisposition::SafeRetry)
            }
            Some(_) => Err(ReplayProtectionError::RequestIdConflict),
            None => {
                state
                    .requests
                    .insert(request_key, *reservation.request_fingerprint());
                Ok(ReplayDisposition::Fresh)
            }
        }
    }
}

fn credential_and_verifier() -> (InstanceCredential, ServiceRequestVerifier<KnownInstance>) {
    let credential = InstanceCredential::generate(ActorId::new());
    let instance = RegisteredInstance::create(
        credential.public_key().clone(),
        "https://worker.example.test",
        900,
        1_100,
    )
    .unwrap();
    (
        credential,
        ServiceRequestVerifier::new(KnownInstance(instance)),
    )
}

fn parts(request_id: Uuid, body: &[u8]) -> ServiceRequestParts {
    ServiceRequestParts::new(
        "POST",
        "kernel.example.test",
        "/v1/subscriptions",
        "application/json",
        body,
        request_id,
    )
    .unwrap()
}

fn verify(
    credential: &InstanceCredential,
    verifier: &ServiceRequestVerifier<KnownInstance>,
    parts: ServiceRequestParts,
    nonce: &str,
) -> VerifiedServiceRequest {
    let signed = SignedServiceRequest::sign(parts, credential, 990, 1_020, nonce).unwrap();
    verifier.verify(&signed, 1_000).unwrap()
}

#[test]
fn exact_wire_replay_is_rejected_after_the_first_atomic_reservation() {
    let (credential, verifier) = credential_and_verifier();
    let request = verify(
        &credential,
        &verifier,
        parts(Uuid::new_v4(), b"{}"),
        "atomic_nonce_0001",
    );
    let protection = ReplayProtectionService::new(MemoryReplayRepository::default());

    assert_eq!(
        protection.protect(request, 1_000),
        Ok(ReplayDisposition::Fresh)
    );
    assert_eq!(
        protection.protect(request, 1_000),
        Err(ReplayProtectionError::ReplayDetected)
    );
}

#[test]
fn same_request_with_a_new_signature_is_a_safe_idempotency_retry() {
    let (credential, verifier) = credential_and_verifier();
    let request_id = Uuid::new_v4();
    let first = verify(
        &credential,
        &verifier,
        parts(request_id, b"{}"),
        "atomic_nonce_0002",
    );
    let retry = verify(
        &credential,
        &verifier,
        parts(request_id, b"{}"),
        "atomic_nonce_0003",
    );
    let protection = ReplayProtectionService::new(MemoryReplayRepository::default());

    assert_eq!(
        protection.protect(first, 1_000),
        Ok(ReplayDisposition::Fresh)
    );
    assert_eq!(
        protection.protect(retry, 1_000),
        Ok(ReplayDisposition::SafeRetry)
    );
}

#[test]
fn request_id_cannot_be_rebound_to_different_semantic_content() {
    let (credential, verifier) = credential_and_verifier();
    let request_id = Uuid::new_v4();
    let first = verify(
        &credential,
        &verifier,
        parts(request_id, br#"{"value":1}"#),
        "atomic_nonce_0004",
    );
    let conflict = verify(
        &credential,
        &verifier,
        parts(request_id, br#"{"value":2}"#),
        "atomic_nonce_0005",
    );
    let protection = ReplayProtectionService::new(MemoryReplayRepository::default());

    assert_eq!(
        protection.protect(first, 1_000),
        Ok(ReplayDisposition::Fresh)
    );
    assert_eq!(
        protection.protect(conflict, 1_000),
        Err(ReplayProtectionError::RequestIdConflict)
    );
}

#[test]
fn concurrent_replays_have_exactly_one_winner() {
    let (credential, verifier) = credential_and_verifier();
    let request = verify(
        &credential,
        &verifier,
        parts(Uuid::new_v4(), b"{}"),
        "atomic_nonce_0006",
    );
    let protection = ReplayProtectionService::new(MemoryReplayRepository::default());
    let outcomes: Vec<_> = (0..16)
        .map(|_| {
            let protection = protection.clone();
            thread::spawn(move || protection.protect(request, 1_000))
        })
        .map(|thread| thread.join().unwrap())
        .collect();

    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome == Ok(ReplayDisposition::Fresh))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome == Err(ReplayProtectionError::ReplayDetected))
            .count(),
        15
    );
}

#[test]
fn nonce_uniqueness_is_scoped_to_the_ephemeral_key() {
    let repository = MemoryReplayRepository::default();
    let protection = ReplayProtectionService::new(repository);
    let (first_credential, first_verifier) = credential_and_verifier();
    let (second_credential, second_verifier) = credential_and_verifier();
    let first = verify(
        &first_credential,
        &first_verifier,
        parts(Uuid::new_v4(), b"{}"),
        "shared_nonce_0001",
    );
    let second = verify(
        &second_credential,
        &second_verifier,
        parts(Uuid::new_v4(), b"{}"),
        "shared_nonce_0001",
    );

    assert_eq!(
        protection.protect(first, 1_000),
        Ok(ReplayDisposition::Fresh)
    );
    assert_eq!(
        protection.protect(second, 1_000),
        Ok(ReplayDisposition::Fresh)
    );
}
