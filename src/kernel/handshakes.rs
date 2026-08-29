//! Goal: discover subscribed service instances and require a fresh, mutually
//! signed proof-of-possession handshake before they become delivery-eligible.

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::sync::Arc;

use sha2::{Digest, Sha256};

use super::instance_keys::{
    InstanceCredential, InstanceId, InstancePublicKey, InstanceSignature, KeyId,
};
use super::instance_registry::RegisteredInstance;

pub const CHALLENGE_LIFETIME_SECONDS: i64 = 15;
pub const HANDSHAKE_LIFETIME_SECONDS: i64 = 30;
const CHALLENGE_CONTEXT: &[u8] = b"infernal-law/instance-handshake/challenge/v1";
const RESPONSE_CONTEXT: &[u8] = b"infernal-law/instance-handshake/response/v1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedHandshakeChallenge {
    nonce: [u8; 32],
    kernel_key: InstancePublicKey,
    target_instance_id: InstanceId,
    target_key_id: KeyId,
    issued_at: i64,
    expires_at: i64,
    signature: InstanceSignature,
}

impl SignedHandshakeChallenge {
    pub fn issue(
        kernel: &InstanceCredential,
        target: &RegisteredInstance,
        now: i64,
    ) -> Result<Self, HandshakeError> {
        if now < 0 || !target.is_eligible_at(now) {
            return Err(HandshakeError::IneligibleInstance(
                target.public_key().instance_id(),
            ));
        }
        let expires_at = now
            .checked_add(CHALLENGE_LIFETIME_SECONDS)
            .ok_or(HandshakeError::InvalidTimestamp)?
            .min(target.lease_expires_at());
        if expires_at <= now {
            return Err(HandshakeError::InvalidTimestamp);
        }
        let mut nonce = [0_u8; 32];
        getrandom::fill(&mut nonce).map_err(|_| HandshakeError::RandomSource)?;
        let kernel_key = kernel.public_key().clone();
        let target_instance_id = target.public_key().instance_id();
        let target_key_id = target.public_key().key_id();
        let message = challenge_message(
            &nonce,
            &kernel_key,
            target_instance_id,
            target_key_id,
            now,
            expires_at,
        );
        Ok(Self {
            nonce,
            kernel_key,
            target_instance_id,
            target_key_id,
            issued_at: now,
            expires_at,
            signature: kernel.sign(&message),
        })
    }

    pub fn verify_kernel(
        &self,
        trusted_kernel_key: &InstancePublicKey,
    ) -> Result<(), HandshakeError> {
        if trusted_kernel_key != &self.kernel_key {
            return Err(HandshakeError::KernelKeyMismatch);
        }
        trusted_kernel_key
            .verify(&self.message(), &self.signature)
            .map_err(|_| HandshakeError::InvalidKernelSignature)
    }

    pub fn digest(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(self.message());
        digest.update(self.signature.as_bytes());
        digest.finalize().into()
    }

    pub const fn kernel_key(&self) -> &InstancePublicKey {
        &self.kernel_key
    }

    pub const fn target_instance_id(&self) -> InstanceId {
        self.target_instance_id
    }

    pub const fn target_key_id(&self) -> KeyId {
        self.target_key_id
    }

    pub const fn issued_at(&self) -> i64 {
        self.issued_at
    }

    pub const fn expires_at(&self) -> i64 {
        self.expires_at
    }

    fn message(&self) -> Vec<u8> {
        challenge_message(
            &self.nonce,
            &self.kernel_key,
            self.target_instance_id,
            self.target_key_id,
            self.issued_at,
            self.expires_at,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedHandshakeResponse {
    kernel_instance_id: InstanceId,
    target_instance_id: InstanceId,
    target_key_id: KeyId,
    challenge_digest: [u8; 32],
    signature: InstanceSignature,
}

impl SignedHandshakeResponse {
    pub fn sign(
        challenge: &SignedHandshakeChallenge,
        target: &InstanceCredential,
    ) -> Result<Self, HandshakeError> {
        if target.public_key().instance_id() != challenge.target_instance_id
            || target.public_key().key_id() != challenge.target_key_id
        {
            return Err(HandshakeError::TargetMismatch);
        }
        let kernel_instance_id = challenge.kernel_key.instance_id();
        let target_instance_id = challenge.target_instance_id;
        let target_key_id = challenge.target_key_id;
        let challenge_digest = challenge.digest();
        let message = response_message(
            kernel_instance_id,
            target_instance_id,
            target_key_id,
            &challenge_digest,
        );
        Ok(Self {
            kernel_instance_id,
            target_instance_id,
            target_key_id,
            challenge_digest,
            signature: target.sign(&message),
        })
    }

    fn verify(
        &self,
        challenge: &SignedHandshakeChallenge,
        target: &InstancePublicKey,
        now: i64,
    ) -> Result<(), HandshakeError> {
        if now < challenge.issued_at || now >= challenge.expires_at {
            return Err(HandshakeError::ChallengeExpired);
        }
        if self.kernel_instance_id != challenge.kernel_key.instance_id()
            || self.target_instance_id != challenge.target_instance_id
            || self.target_key_id != challenge.target_key_id
            || self.challenge_digest != challenge.digest()
            || target.instance_id() != self.target_instance_id
            || target.key_id() != self.target_key_id
        {
            return Err(HandshakeError::TargetMismatch);
        }
        target
            .verify(
                &response_message(
                    self.kernel_instance_id,
                    self.target_instance_id,
                    self.target_key_id,
                    &self.challenge_digest,
                ),
                &self.signature,
            )
            .map_err(|_| HandshakeError::InvalidTargetSignature)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstanceHandshake {
    challenge_digest: [u8; 32],
    kernel_instance_id: InstanceId,
    target_instance_id: InstanceId,
    target_key_id: KeyId,
    verified_at: i64,
    expires_at: i64,
}

impl InstanceHandshake {
    pub fn restore(
        challenge_digest: [u8; 32],
        kernel_instance_id: InstanceId,
        target_instance_id: InstanceId,
        target_key_id: KeyId,
        verified_at: i64,
        expires_at: i64,
    ) -> Result<Self, HandshakeError> {
        if verified_at < 0 || expires_at <= verified_at {
            return Err(HandshakeError::InvalidStoredRecord);
        }
        Ok(Self {
            challenge_digest,
            kernel_instance_id,
            target_instance_id,
            target_key_id,
            verified_at,
            expires_at,
        })
    }

    pub const fn challenge_digest(&self) -> &[u8; 32] {
        &self.challenge_digest
    }
    pub const fn kernel_instance_id(&self) -> InstanceId {
        self.kernel_instance_id
    }
    pub const fn target_instance_id(&self) -> InstanceId {
        self.target_instance_id
    }
    pub const fn target_key_id(&self) -> KeyId {
        self.target_key_id
    }
    pub const fn verified_at(&self) -> i64 {
        self.verified_at
    }
    pub const fn expires_at(&self) -> i64 {
        self.expires_at
    }
    pub fn is_fresh_at(&self, now: i64) -> bool {
        now >= self.verified_at && now < self.expires_at
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HandshakeChallengeRecord {
    digest: [u8; 32],
    kernel_instance_id: InstanceId,
    target_instance_id: InstanceId,
    target_key_id: KeyId,
    issued_at: i64,
    expires_at: i64,
}

impl From<&SignedHandshakeChallenge> for HandshakeChallengeRecord {
    fn from(challenge: &SignedHandshakeChallenge) -> Self {
        Self {
            digest: challenge.digest(),
            kernel_instance_id: challenge.kernel_key.instance_id(),
            target_instance_id: challenge.target_instance_id,
            target_key_id: challenge.target_key_id,
            issued_at: challenge.issued_at,
            expires_at: challenge.expires_at,
        }
    }
}

impl HandshakeChallengeRecord {
    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
    pub const fn kernel_instance_id(&self) -> InstanceId {
        self.kernel_instance_id
    }
    pub const fn target_instance_id(&self) -> InstanceId {
        self.target_instance_id
    }
    pub const fn target_key_id(&self) -> KeyId {
        self.target_key_id
    }
    pub const fn issued_at(&self) -> i64 {
        self.issued_at
    }
    pub const fn expires_at(&self) -> i64 {
        self.expires_at
    }
}

pub trait SubscribedInstanceDiscovery: Send + Sync {
    fn eligible_subscribed_instances(
        &self,
        now: i64,
    ) -> Result<Vec<RegisteredInstance>, HandshakeError>;
}

pub trait HandshakeRepository: Send + Sync {
    fn insert_challenge(&self, challenge: HandshakeChallengeRecord) -> Result<(), HandshakeError>;
    fn complete(&self, handshake: InstanceHandshake) -> Result<(), HandshakeError>;
    fn find_fresh(
        &self,
        kernel_instance_id: InstanceId,
        target_instance_id: InstanceId,
        now: i64,
    ) -> Result<Option<InstanceHandshake>, HandshakeError>;
}

pub trait HandshakeTransport: Send + Sync {
    fn exchange(
        &self,
        endpoint: &str,
        challenge: &SignedHandshakeChallenge,
    ) -> Result<HandshakeExchange, HandshakeError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HandshakeExchange {
    pub response: SignedHandshakeResponse,
    pub received_at: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HandshakeAttemptOutcome {
    AlreadyFresh(InstanceHandshake),
    Verified(InstanceHandshake),
    Failed(HandshakeError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HandshakeAttempt {
    pub instance_id: InstanceId,
    pub outcome: HandshakeAttemptOutcome,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReconcileReport {
    pub attempts: Vec<HandshakeAttempt>,
}

pub struct HandshakeReconciler<D, H, T> {
    kernel: Arc<InstanceCredential>,
    discovery: D,
    handshakes: H,
    transport: T,
}

impl<D, H, T> HandshakeReconciler<D, H, T>
where
    D: SubscribedInstanceDiscovery,
    H: HandshakeRepository,
    T: HandshakeTransport,
{
    pub const fn new(
        kernel: Arc<InstanceCredential>,
        discovery: D,
        handshakes: H,
        transport: T,
    ) -> Self {
        Self {
            kernel,
            discovery,
            handshakes,
            transport,
        }
    }

    pub fn reconcile(&self, now: i64) -> Result<ReconcileReport, HandshakeError> {
        if now < 0 {
            return Err(HandshakeError::InvalidTimestamp);
        }
        let candidates = self.discovery.eligible_subscribed_instances(now)?;
        let mut attempts = Vec::with_capacity(candidates.len());
        for instance in candidates {
            let instance_id = instance.public_key().instance_id();
            let outcome = match self.reconcile_instance(&instance, now) {
                Ok(outcome) => outcome,
                Err(error) => HandshakeAttemptOutcome::Failed(error),
            };
            attempts.push(HandshakeAttempt {
                instance_id,
                outcome,
            });
        }
        Ok(ReconcileReport { attempts })
    }

    pub fn require_fresh(
        &self,
        target_instance_id: InstanceId,
        now: i64,
    ) -> Result<InstanceHandshake, HandshakeError> {
        self.handshakes
            .find_fresh(
                self.kernel.public_key().instance_id(),
                target_instance_id,
                now,
            )?
            .ok_or(HandshakeError::HandshakeRequired(target_instance_id))
    }

    fn reconcile_instance(
        &self,
        instance: &RegisteredInstance,
        now: i64,
    ) -> Result<HandshakeAttemptOutcome, HandshakeError> {
        let kernel_instance_id = self.kernel.public_key().instance_id();
        let target_instance_id = instance.public_key().instance_id();
        if let Some(existing) =
            self.handshakes
                .find_fresh(kernel_instance_id, target_instance_id, now)?
        {
            return Ok(HandshakeAttemptOutcome::AlreadyFresh(existing));
        }
        let challenge = SignedHandshakeChallenge::issue(&self.kernel, instance, now)?;
        self.handshakes.insert_challenge((&challenge).into())?;
        let exchange = self.transport.exchange(instance.endpoint(), &challenge)?;
        exchange
            .response
            .verify(&challenge, instance.public_key(), exchange.received_at)?;
        let expires_at = exchange
            .received_at
            .checked_add(HANDSHAKE_LIFETIME_SECONDS)
            .ok_or(HandshakeError::InvalidTimestamp)?
            .min(instance.lease_expires_at());
        let handshake = InstanceHandshake::restore(
            challenge.digest(),
            kernel_instance_id,
            target_instance_id,
            instance.public_key().key_id(),
            exchange.received_at,
            expires_at,
        )?;
        self.handshakes.complete(handshake.clone())?;
        Ok(HandshakeAttemptOutcome::Verified(handshake))
    }
}

fn challenge_message(
    nonce: &[u8; 32],
    kernel_key: &InstancePublicKey,
    target_instance_id: InstanceId,
    target_key_id: KeyId,
    issued_at: i64,
    expires_at: i64,
) -> Vec<u8> {
    encode_fields(&[
        CHALLENGE_CONTEXT,
        nonce,
        kernel_key.service_id().as_uuid().as_bytes(),
        kernel_key.instance_id().as_uuid().as_bytes(),
        kernel_key.key_id().as_uuid().as_bytes(),
        kernel_key.public_key_bytes(),
        target_instance_id.as_uuid().as_bytes(),
        target_key_id.as_uuid().as_bytes(),
        &issued_at.to_be_bytes(),
        &expires_at.to_be_bytes(),
    ])
}

fn response_message(
    kernel_instance_id: InstanceId,
    target_instance_id: InstanceId,
    target_key_id: KeyId,
    challenge_digest: &[u8; 32],
) -> Vec<u8> {
    encode_fields(&[
        RESPONSE_CONTEXT,
        kernel_instance_id.as_uuid().as_bytes(),
        target_instance_id.as_uuid().as_bytes(),
        target_key_id.as_uuid().as_bytes(),
        challenge_digest,
    ])
}

fn encode_fields(fields: &[&[u8]]) -> Vec<u8> {
    let mut message = Vec::new();
    for field in fields {
        message.extend_from_slice(&(field.len() as u32).to_be_bytes());
        message.extend_from_slice(field);
    }
    message
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HandshakeError {
    ChallengeAlreadyUsed,
    ChallengeExpired,
    HandshakeRequired(InstanceId),
    IneligibleInstance(InstanceId),
    InvalidKernelSignature,
    InvalidStoredRecord,
    InvalidTargetSignature,
    InvalidTimestamp,
    KernelKeyMismatch,
    RandomSource,
    Repository(String),
    TargetMismatch,
    Transport(String),
}

impl Display for HandshakeError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::ChallengeAlreadyUsed => {
                formatter.write_str("handshake challenge is expired or already used")
            }
            Self::ChallengeExpired => formatter.write_str("handshake challenge has expired"),
            Self::HandshakeRequired(id) => {
                write!(formatter, "instance {id} requires a fresh handshake")
            }
            Self::IneligibleInstance(id) => {
                write!(formatter, "instance {id} is not eligible for handshake")
            }
            Self::InvalidKernelSignature => {
                formatter.write_str("kernel handshake signature is invalid")
            }
            Self::InvalidStoredRecord => formatter.write_str("stored handshake record is invalid"),
            Self::InvalidTargetSignature => {
                formatter.write_str("target handshake signature is invalid")
            }
            Self::InvalidTimestamp => formatter.write_str("handshake timestamp is invalid"),
            Self::KernelKeyMismatch => formatter.write_str("kernel handshake key is not trusted"),
            Self::RandomSource => formatter.write_str("operating system random source failed"),
            Self::Repository(message) => {
                write!(formatter, "handshake repository failed: {message}")
            }
            Self::TargetMismatch => {
                formatter.write_str("handshake response does not match its target")
            }
            Self::Transport(message) => write!(formatter, "handshake transport failed: {message}"),
        }
    }
}

impl Error for HandshakeError {}
