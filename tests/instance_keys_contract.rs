//! Goal: verify the public per-instance key contract independently of HTTP,
//! PostgreSQL, Kubernetes, and the future kernel registration contract.

use infernal_law::kernel::identity::ActorId;
use infernal_law::kernel::instance_keys::{
    ALGORITHM, InstanceCredential, InstanceKeyError, InstancePublicKey,
};

#[test]
fn each_instance_has_a_unique_public_identity_and_working_key() {
    let service_id = ActorId::new();
    let first = InstanceCredential::generate(service_id);
    let second = InstanceCredential::generate(service_id);
    let challenge = b"fresh kernel nonce";

    assert_eq!(first.public_key().service_id(), service_id);
    assert_eq!(first.public_key().algorithm(), ALGORITHM);
    assert_ne!(
        first.public_key().instance_id(),
        second.public_key().instance_id()
    );
    assert_ne!(first.public_key().key_id(), second.public_key().key_id());
    assert_ne!(
        first.public_key().public_key_bytes(),
        second.public_key().public_key_bytes()
    );

    let proof = first.sign(challenge);
    let registry_copy = InstancePublicKey::restore(
        first.public_key().service_id(),
        first.public_key().instance_id(),
        first.public_key().key_id(),
        *first.public_key().public_key_bytes(),
    )
    .unwrap();
    assert!(registry_copy.verify(challenge, &proof).is_ok());
    assert_eq!(
        second.public_key().verify(challenge, &proof),
        Err(InstanceKeyError::InvalidSignature)
    );
}

#[test]
fn changing_a_signed_challenge_invalidates_the_proof() {
    let instance = InstanceCredential::generate(ActorId::new());
    let proof = instance.sign(b"challenge-a");

    assert_eq!(
        instance.public_key().verify(b"challenge-b", &proof),
        Err(InstanceKeyError::InvalidSignature)
    );
}
