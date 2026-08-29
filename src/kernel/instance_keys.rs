//! Goal: give each running service process a unique, ephemeral signing key
//! while exposing only the public material needed for verification.

use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};
use std::str::FromStr;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use getrandom::{SysRng, rand_core::UnwrapErr};
use uuid::Uuid;

use super::identity::ActorId;

pub const ALGORITHM: &str = "ed25519";
pub const PUBLIC_KEY_LENGTH: usize = 32;
pub const SIGNATURE_LENGTH: usize = 64;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct InstanceId(Uuid);

impl InstanceId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    pub const fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

impl Default for InstanceId {
    fn default() -> Self {
        Self::new()
    }
}

impl Display for InstanceId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.0, formatter)
    }
}

impl FromStr for InstanceId {
    type Err = InstanceKeyError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(value)
            .map(Self)
            .map_err(|_| InstanceKeyError::InvalidInstanceId)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct KeyId(Uuid);

impl KeyId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    pub const fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

impl Default for KeyId {
    fn default() -> Self {
        Self::new()
    }
}

impl Display for KeyId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.0, formatter)
    }
}

impl FromStr for KeyId {
    type Err = InstanceKeyError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(value)
            .map(Self)
            .map_err(|_| InstanceKeyError::InvalidKeyId)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstancePublicKey {
    service_id: ActorId,
    instance_id: InstanceId,
    key_id: KeyId,
    public_key: [u8; PUBLIC_KEY_LENGTH],
}

impl InstancePublicKey {
    pub fn restore(
        service_id: ActorId,
        instance_id: InstanceId,
        key_id: KeyId,
        public_key: [u8; PUBLIC_KEY_LENGTH],
    ) -> Result<Self, InstanceKeyError> {
        VerifyingKey::from_bytes(&public_key).map_err(|_| InstanceKeyError::InvalidPublicKey)?;
        Ok(Self {
            service_id,
            instance_id,
            key_id,
            public_key,
        })
    }

    pub const fn service_id(&self) -> ActorId {
        self.service_id
    }

    pub const fn instance_id(&self) -> InstanceId {
        self.instance_id
    }

    pub const fn key_id(&self) -> KeyId {
        self.key_id
    }

    pub const fn algorithm(&self) -> &'static str {
        ALGORITHM
    }

    pub const fn public_key_bytes(&self) -> &[u8; PUBLIC_KEY_LENGTH] {
        &self.public_key
    }

    pub fn verify(
        &self,
        message: &[u8],
        signature: &InstanceSignature,
    ) -> Result<(), InstanceKeyError> {
        let verifying_key = VerifyingKey::from_bytes(&self.public_key)
            .map_err(|_| InstanceKeyError::InvalidPublicKey)?;
        verifying_key
            .verify_strict(message, &Signature::from_bytes(&signature.0))
            .map_err(|_| InstanceKeyError::InvalidSignature)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct InstanceSignature([u8; SIGNATURE_LENGTH]);

impl InstanceSignature {
    pub const fn from_bytes(bytes: [u8; SIGNATURE_LENGTH]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; SIGNATURE_LENGTH] {
        &self.0
    }
}

impl Debug for InstanceSignature {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("InstanceSignature([redacted])")
    }
}

pub struct InstanceCredential {
    public_key: InstancePublicKey,
    signing_key: SigningKey,
}

impl InstanceCredential {
    pub fn generate(service_id: ActorId) -> Self {
        let signing_key = SigningKey::generate(&mut UnwrapErr(SysRng));
        let public_key = InstancePublicKey {
            service_id,
            instance_id: InstanceId::new(),
            key_id: KeyId::new(),
            public_key: signing_key.verifying_key().to_bytes(),
        };

        Self {
            public_key,
            signing_key,
        }
    }

    pub const fn public_key(&self) -> &InstancePublicKey {
        &self.public_key
    }

    pub fn sign(&self, message: &[u8]) -> InstanceSignature {
        InstanceSignature(self.signing_key.sign(message).to_bytes())
    }
}

impl Debug for InstanceCredential {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InstanceCredential")
            .field("public_key", &self.public_key)
            .field("signing_key", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InstanceKeyError {
    InvalidInstanceId,
    InvalidKeyId,
    InvalidPublicKey,
    InvalidSignature,
}

impl Display for InstanceKeyError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInstanceId => formatter.write_str("instance ID must be a valid UUID"),
            Self::InvalidKeyId => formatter.write_str("key ID must be a valid UUID"),
            Self::InvalidPublicKey => formatter.write_str("public key is not valid Ed25519"),
            Self::InvalidSignature => formatter.write_str("signature verification failed"),
        }
    }
}

impl Error for InstanceKeyError {}

#[cfg(test)]
mod tests {
    use super::{InstanceCredential, InstanceKeyError};
    use crate::kernel::identity::ActorId;

    #[test]
    fn generates_a_distinct_instance_and_key_for_each_process_credential() {
        let service_id = ActorId::new();
        let first = InstanceCredential::generate(service_id);
        let second = InstanceCredential::generate(service_id);

        assert_eq!(first.public_key().service_id(), service_id);
        assert_eq!(second.public_key().service_id(), service_id);
        assert_ne!(
            first.public_key().instance_id(),
            second.public_key().instance_id()
        );
        assert_ne!(first.public_key().key_id(), second.public_key().key_id());
        assert_ne!(
            first.public_key().public_key_bytes(),
            second.public_key().public_key_bytes()
        );
    }

    #[test]
    fn public_key_verifies_only_the_original_message() {
        let credential = InstanceCredential::generate(ActorId::new());
        let signature = credential.sign(b"kernel challenge");

        assert!(
            credential
                .public_key()
                .verify(b"kernel challenge", &signature)
                .is_ok()
        );
        assert_eq!(
            credential
                .public_key()
                .verify(b"altered challenge", &signature),
            Err(InstanceKeyError::InvalidSignature)
        );
    }

    #[test]
    fn debug_output_never_contains_private_or_signature_bytes() {
        let credential = InstanceCredential::generate(ActorId::new());
        let signature = credential.sign(b"message");

        assert!(format!("{credential:?}").contains("[redacted]"));
        assert_eq!(format!("{signature:?}"), "InstanceSignature([redacted])");
    }
}
