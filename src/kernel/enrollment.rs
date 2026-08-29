//! Goal: authenticate a newly discovered Kubernetes workload before its
//! ephemeral public key and lease enter the kernel-owned instance registry.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

use sha2::{Digest, Sha256};

use super::identity::ActorId;
use super::instance_keys::{InstanceCredential, InstancePublicKey, InstanceSignature};
use super::instance_registry::{
    InstanceRegistryError, InstanceRegistryRepository, InstanceRegistryService, RegisteredInstance,
};

pub const ENROLLMENT_AUDIENCE: &str = "infernal-law-enrollment";
pub const CHALLENGE_LIFETIME_SECONDS: i64 = 30;
const PROOF_CONTEXT: &[u8] = b"infernal-law/enrollment/v1";
const CHALLENGE_LENGTH: usize = 32;
const MAX_NAME_LENGTH: usize = 253;
const MAX_UID_LENGTH: usize = 253;
const MAX_TOKEN_LENGTH: usize = 32 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnrollmentChallenge([u8; CHALLENGE_LENGTH]);

impl EnrollmentChallenge {
    pub fn generate() -> Self {
        let mut bytes = [0_u8; CHALLENGE_LENGTH];
        getrandom::fill(&mut bytes)
            .unwrap_or_else(|error| panic!("operating system random source failed: {error}"));
        Self(bytes)
    }

    pub const fn from_bytes(bytes: [u8; CHALLENGE_LENGTH]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; CHALLENGE_LENGTH] {
        &self.0
    }
}

impl Default for EnrollmentChallenge {
    fn default() -> Self {
        Self::generate()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedWorkload {
    namespace: String,
    service_account: String,
    service_account_uid: String,
    pod_name: String,
    pod_uid: String,
    audiences: Vec<String>,
}

impl VerifiedWorkload {
    pub fn new(
        namespace: &str,
        service_account: &str,
        service_account_uid: &str,
        pod_name: &str,
        pod_uid: &str,
        audiences: Vec<String>,
    ) -> Result<Self, EnrollmentError> {
        Ok(Self {
            namespace: validate_field(namespace, MAX_NAME_LENGTH)?,
            service_account: validate_field(service_account, MAX_NAME_LENGTH)?,
            service_account_uid: validate_field(service_account_uid, MAX_UID_LENGTH)?,
            pod_name: validate_field(pod_name, MAX_NAME_LENGTH)?,
            pod_uid: validate_field(pod_uid, MAX_UID_LENGTH)?,
            audiences,
        })
    }

    pub fn namespace(&self) -> &str {
        &self.namespace
    }
    pub fn service_account(&self) -> &str {
        &self.service_account
    }
    pub fn service_account_uid(&self) -> &str {
        &self.service_account_uid
    }
    pub fn pod_name(&self) -> &str {
        &self.pod_name
    }
    pub fn pod_uid(&self) -> &str {
        &self.pod_uid
    }
    pub fn audiences(&self) -> &[String] {
        &self.audiences
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnrollmentBinding {
    service_id: ActorId,
    namespace: String,
    service_account: String,
    service_account_uid: String,
    enabled: bool,
}

impl EnrollmentBinding {
    pub fn new_disabled(
        service_id: ActorId,
        namespace: &str,
        service_account: &str,
        service_account_uid: &str,
    ) -> Result<Self, EnrollmentError> {
        Self::restore(
            service_id,
            namespace,
            service_account,
            service_account_uid,
            false,
        )
    }

    pub fn restore(
        service_id: ActorId,
        namespace: &str,
        service_account: &str,
        service_account_uid: &str,
        enabled: bool,
    ) -> Result<Self, EnrollmentError> {
        Ok(Self {
            service_id,
            namespace: validate_field(namespace, MAX_NAME_LENGTH)?,
            service_account: validate_field(service_account, MAX_NAME_LENGTH)?,
            service_account_uid: validate_field(service_account_uid, MAX_UID_LENGTH)?,
            enabled,
        })
    }

    pub const fn service_id(&self) -> ActorId {
        self.service_id
    }
    pub fn namespace(&self) -> &str {
        &self.namespace
    }
    pub fn service_account(&self) -> &str {
        &self.service_account
    }
    pub fn service_account_uid(&self) -> &str {
        &self.service_account_uid
    }
    pub const fn enabled(&self) -> bool {
        self.enabled
    }
}

pub struct EnrollmentRequest {
    challenge: EnrollmentChallenge,
    public_key: InstancePublicKey,
    endpoint: String,
    claimed_pod_uid: String,
    workload_token: String,
    signature: InstanceSignature,
}

impl EnrollmentRequest {
    pub fn sign(
        credential: &InstanceCredential,
        challenge: EnrollmentChallenge,
        endpoint: &str,
        claimed_pod_uid: &str,
        workload_token: String,
    ) -> Result<Self, EnrollmentError> {
        let endpoint = validate_field(endpoint, 2048)?;
        let claimed_pod_uid = validate_field(claimed_pod_uid, MAX_UID_LENGTH)?;
        if workload_token.is_empty() || workload_token.len() > MAX_TOKEN_LENGTH {
            return Err(EnrollmentError::InvalidField);
        }
        let public_key = credential.public_key().clone();
        let message = proof_message(
            &challenge,
            &public_key,
            &endpoint,
            &claimed_pod_uid,
            &workload_token,
        );
        let signature = credential.sign(&message);
        Ok(Self {
            challenge,
            public_key,
            endpoint,
            claimed_pod_uid,
            workload_token,
            signature,
        })
    }

    pub fn public_key(&self) -> &InstancePublicKey {
        &self.public_key
    }
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }
}

pub trait WorkloadTokenReviewer: Send + Sync {
    fn review(&self, token: &str, audience: &str) -> Result<VerifiedWorkload, EnrollmentError>;
}

pub trait EnrollmentBindingRepository: Send + Sync {
    fn insert_disabled(&self, binding: EnrollmentBinding) -> Result<(), EnrollmentError>;
    fn set_enabled(&self, service_id: ActorId, enabled: bool) -> Result<(), EnrollmentError>;
    fn find_workload(
        &self,
        namespace: &str,
        service_account: &str,
        service_account_uid: &str,
    ) -> Result<Option<EnrollmentBinding>, EnrollmentError>;
    fn insert_challenge(
        &self,
        service_id: ActorId,
        challenge: EnrollmentChallenge,
        expires_at: i64,
    ) -> Result<(), EnrollmentError>;
    fn consume_challenge(
        &self,
        service_id: ActorId,
        challenge: EnrollmentChallenge,
        now: i64,
    ) -> Result<(), EnrollmentError>;
}

pub struct EnrollmentService<A, B, R> {
    reviewer: A,
    bindings: B,
    registry: InstanceRegistryService<R>,
}

impl<A, B, R> EnrollmentService<A, B, R>
where
    A: WorkloadTokenReviewer,
    B: EnrollmentBindingRepository,
    R: InstanceRegistryRepository,
{
    pub const fn new(reviewer: A, bindings: B, registry: InstanceRegistryService<R>) -> Self {
        Self {
            reviewer,
            bindings,
            registry,
        }
    }

    pub fn issue_challenge(
        &self,
        service_id: ActorId,
        now: i64,
    ) -> Result<EnrollmentChallenge, EnrollmentError> {
        if now < 0 {
            return Err(EnrollmentError::InvalidField);
        }
        let expires_at = now
            .checked_add(CHALLENGE_LIFETIME_SECONDS)
            .ok_or(EnrollmentError::InvalidField)?;
        let challenge = EnrollmentChallenge::generate();
        self.bindings
            .insert_challenge(service_id, challenge, expires_at)?;
        Ok(challenge)
    }

    pub fn authenticate_and_register(
        &self,
        request: EnrollmentRequest,
        now: i64,
    ) -> Result<RegisteredInstance, EnrollmentError> {
        let message = proof_message(
            &request.challenge,
            &request.public_key,
            &request.endpoint,
            &request.claimed_pod_uid,
            &request.workload_token,
        );
        request
            .public_key
            .verify(&message, &request.signature)
            .map_err(|_| EnrollmentError::InvalidProof)?;

        let workload = self
            .reviewer
            .review(&request.workload_token, ENROLLMENT_AUDIENCE)?;
        if !workload
            .audiences
            .iter()
            .any(|value| value == ENROLLMENT_AUDIENCE)
        {
            return Err(EnrollmentError::AudienceMismatch);
        }
        if workload.pod_uid != request.claimed_pod_uid {
            return Err(EnrollmentError::PodMismatch);
        }
        let binding = self
            .bindings
            .find_workload(
                &workload.namespace,
                &workload.service_account,
                &workload.service_account_uid,
            )?
            .ok_or(EnrollmentError::BindingNotFound)?;
        if !binding.enabled {
            return Err(EnrollmentError::BindingDisabled);
        }
        if binding.service_id != request.public_key.service_id() {
            return Err(EnrollmentError::ServiceMismatch);
        }
        self.bindings
            .consume_challenge(request.public_key.service_id(), request.challenge, now)?;

        self.registry
            .register_verified(request.public_key, &request.endpoint, now)
            .map_err(EnrollmentError::Registry)
    }
}

fn proof_message(
    challenge: &EnrollmentChallenge,
    public_key: &InstancePublicKey,
    endpoint: &str,
    pod_uid: &str,
    token: &str,
) -> Vec<u8> {
    let token_digest: [u8; 32] = Sha256::digest(token.as_bytes()).into();
    let service_id = public_key.service_id();
    let instance_id = public_key.instance_id();
    let key_id = public_key.key_id();
    let fields: [&[u8]; 8] = [
        PROOF_CONTEXT,
        challenge.as_bytes(),
        service_id.as_uuid().as_bytes(),
        instance_id.as_uuid().as_bytes(),
        key_id.as_uuid().as_bytes(),
        public_key.public_key_bytes(),
        endpoint.as_bytes(),
        pod_uid.as_bytes(),
    ];
    let mut message = Vec::new();
    for field in fields.into_iter().chain([token_digest.as_slice()]) {
        message.extend_from_slice(&(field.len() as u32).to_be_bytes());
        message.extend_from_slice(field);
    }
    message
}

fn validate_field(value: &str, max: usize) -> Result<String, EnrollmentError> {
    let value = value.trim();
    if value.is_empty() || value.len() > max || value.contains('\0') {
        return Err(EnrollmentError::InvalidField);
    }
    Ok(value.to_owned())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EnrollmentError {
    AudienceMismatch,
    BindingDisabled,
    BindingNotFound,
    ChallengeRejected,
    InvalidField,
    InvalidProof,
    PodMismatch,
    Repository(String),
    Registry(InstanceRegistryError),
    ServiceMismatch,
    TokenRejected,
}

impl Display for EnrollmentError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::AudienceMismatch => {
                formatter.write_str("workload token audience was not accepted")
            }
            Self::BindingDisabled => formatter.write_str("workload enrollment binding is disabled"),
            Self::BindingNotFound => formatter.write_str("workload has no enrollment binding"),
            Self::ChallengeRejected => {
                formatter.write_str("enrollment challenge is unknown, expired, or already consumed")
            }
            Self::InvalidField => {
                formatter.write_str("enrollment request contains an invalid field")
            }
            Self::InvalidProof => formatter.write_str("instance enrollment proof is invalid"),
            Self::PodMismatch => {
                formatter.write_str("verified Pod does not match the signed enrollment proof")
            }
            Self::Repository(message) => {
                write!(formatter, "enrollment binding repository failed: {message}")
            }
            Self::Registry(error) => Display::fmt(error, formatter),
            Self::ServiceMismatch => {
                formatter.write_str("workload is not bound to the proposed service identity")
            }
            Self::TokenRejected => formatter.write_str("workload token was rejected"),
        }
    }
}

impl Error for EnrollmentError {}
