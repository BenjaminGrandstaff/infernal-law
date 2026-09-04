//! Goal: define a strict JSON wire format for initial enrollment without
//! exposing bearer tokens or signature material through debug output.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

use crate::kernel::enrollment::{
    CHALLENGE_LIFETIME_SECONDS, ENROLLMENT_AUDIENCE, EnrollmentChallenge, EnrollmentError,
    EnrollmentRequest,
};
use crate::kernel::identity::ActorId;
use crate::kernel::instance_keys::{
    ALGORITHM, InstanceCredential, InstanceId, InstancePublicKey, InstanceSignature, KeyId,
    PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH,
};
use crate::kernel::instance_registry::RegisteredInstance;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentChallengeRequest {
    pub service_id: String,
}

impl EnrollmentChallengeRequest {
    pub fn service_id(&self) -> Result<ActorId, EnrollmentDtoError> {
        self.service_id
            .parse()
            .map_err(|_| EnrollmentDtoError::InvalidServiceId)
    }
}

/// A challenge request made by the workload itself rather than by an
/// operator naming a service. The service ID is deliberately absent: it is
/// derived from the enrollment binding the token resolves to, so a workload
/// cannot ask for a challenge belonging to an identity it may not become.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadChallengeRequest {
    pub pod_uid: String,
    pub workload_token: String,
}

/// Debug is written by hand, not derived: this type carries a bearer token,
/// and the derived form would print it into any log line that formats a
/// request.
impl fmt::Debug for WorkloadChallengeRequest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkloadChallengeRequest")
            .field("pod_uid", &self.pod_uid)
            .field("workload_token", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentChallengeResponse {
    pub service_id: String,
    pub challenge: String,
    pub audience: String,
    pub expires_at: i64,
}

impl EnrollmentChallengeResponse {
    pub fn new(
        service_id: ActorId,
        challenge: EnrollmentChallenge,
        issued_at: i64,
    ) -> Result<Self, EnrollmentDtoError> {
        let expires_at = issued_at
            .checked_add(CHALLENGE_LIFETIME_SECONDS)
            .ok_or(EnrollmentDtoError::InvalidTimestamp)?;
        if issued_at < 0 {
            return Err(EnrollmentDtoError::InvalidTimestamp);
        }
        Ok(Self {
            service_id: service_id.to_string(),
            challenge: encode(challenge.as_bytes()),
            audience: ENROLLMENT_AUDIENCE.to_owned(),
            expires_at,
        })
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentSubmissionRequest {
    service_id: String,
    instance_id: String,
    key_id: String,
    algorithm: String,
    public_key: String,
    challenge: String,
    endpoint: String,
    pod_uid: String,
    workload_token: String,
    signature: String,
}

impl EnrollmentSubmissionRequest {
    pub fn sign(
        credential: &InstanceCredential,
        challenge: EnrollmentChallenge,
        endpoint: &str,
        pod_uid: &str,
        workload_token: String,
    ) -> Result<Self, EnrollmentDtoError> {
        let request =
            EnrollmentRequest::sign(credential, challenge, endpoint, pod_uid, workload_token)
                .map_err(|_| EnrollmentDtoError::InvalidEnrollment)?;
        Ok(Self::from_domain(request))
    }

    pub fn into_domain(self) -> Result<EnrollmentRequest, EnrollmentDtoError> {
        if self.algorithm != ALGORITHM {
            return Err(EnrollmentDtoError::UnsupportedAlgorithm);
        }
        let service_id = self
            .service_id
            .parse::<ActorId>()
            .map_err(|_| EnrollmentDtoError::InvalidServiceId)?;
        let instance_id = self
            .instance_id
            .parse::<InstanceId>()
            .map_err(|_| EnrollmentDtoError::InvalidInstanceId)?;
        let key_id = self
            .key_id
            .parse::<KeyId>()
            .map_err(|_| EnrollmentDtoError::InvalidKeyId)?;
        let public_key = InstancePublicKey::restore(
            service_id,
            instance_id,
            key_id,
            decode_fixed::<PUBLIC_KEY_LENGTH>(&self.public_key)
                .map_err(|_| EnrollmentDtoError::InvalidPublicKey)?,
        )
        .map_err(|_| EnrollmentDtoError::InvalidPublicKey)?;
        let challenge = EnrollmentChallenge::from_bytes(
            decode_fixed::<32>(&self.challenge)
                .map_err(|_| EnrollmentDtoError::InvalidChallenge)?,
        );
        let signature = InstanceSignature::from_bytes(
            decode_fixed::<SIGNATURE_LENGTH>(&self.signature)
                .map_err(|_| EnrollmentDtoError::InvalidSignature)?,
        );
        EnrollmentRequest::restore(
            challenge,
            public_key,
            &self.endpoint,
            &self.pod_uid,
            self.workload_token,
            signature,
        )
        .map_err(|_| EnrollmentDtoError::InvalidEnrollment)
    }

    fn from_domain(request: EnrollmentRequest) -> Self {
        let parts = request.into_transport_parts();
        Self {
            service_id: parts.public_key.service_id().to_string(),
            instance_id: parts.public_key.instance_id().to_string(),
            key_id: parts.public_key.key_id().to_string(),
            algorithm: parts.public_key.algorithm().to_owned(),
            public_key: encode(parts.public_key.public_key_bytes()),
            challenge: encode(parts.challenge.as_bytes()),
            endpoint: parts.endpoint,
            pod_uid: parts.claimed_pod_uid,
            workload_token: parts.workload_token,
            signature: encode(parts.signature.as_bytes()),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentSuccessResponse {
    pub service_id: String,
    pub instance_id: String,
    pub key_id: String,
    pub algorithm: String,
    pub endpoint: String,
    pub registered_at: i64,
    pub lease_expires_at: i64,
    pub lease_revision: i64,
}

impl From<&RegisteredInstance> for EnrollmentSuccessResponse {
    fn from(instance: &RegisteredInstance) -> Self {
        let key = instance.public_key();
        Self {
            service_id: key.service_id().to_string(),
            instance_id: key.instance_id().to_string(),
            key_id: key.key_id().to_string(),
            algorithm: key.algorithm().to_owned(),
            endpoint: instance.endpoint().to_owned(),
            registered_at: instance.registered_at(),
            lease_expires_at: instance.lease_expires_at(),
            lease_revision: instance.lease_revision(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentErrorResponse {
    pub code: String,
    pub message: String,
}

impl EnrollmentErrorResponse {
    pub fn malformed_request() -> Self {
        Self::new(
            "invalid_enrollment_request",
            "enrollment request is invalid",
        )
    }

    pub fn from_enrollment_error(error: &EnrollmentError) -> Self {
        match error {
            EnrollmentError::AudienceMismatch
            | EnrollmentError::BindingDisabled
            | EnrollmentError::BindingNotFound
            | EnrollmentError::ChallengeRejected
            | EnrollmentError::InvalidProof
            | EnrollmentError::PodMismatch
            | EnrollmentError::ServiceMismatch
            | EnrollmentError::TokenRejected => Self::new(
                "enrollment_rejected",
                "enrollment authentication was rejected",
            ),
            EnrollmentError::InvalidField => Self::malformed_request(),
            EnrollmentError::Registry(_) | EnrollmentError::Repository(_) => {
                Self::new("internal_error", "enrollment could not be completed")
            }
        }
    }

    fn new(code: &str, message: &str) -> Self {
        Self {
            code: code.to_owned(),
            message: message.to_owned(),
        }
    }
}

fn encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn decode_fixed<const N: usize>(value: &str) -> Result<[u8; N], EnrollmentDtoError> {
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| EnrollmentDtoError::InvalidEncoding)?;
    decoded
        .try_into()
        .map_err(|_| EnrollmentDtoError::InvalidEncoding)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EnrollmentDtoError {
    InvalidChallenge,
    InvalidEncoding,
    InvalidEnrollment,
    InvalidInstanceId,
    InvalidKeyId,
    InvalidPublicKey,
    InvalidServiceId,
    InvalidSignature,
    InvalidTimestamp,
    UnsupportedAlgorithm,
}

impl Display for EnrollmentDtoError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("enrollment JSON payload is invalid")
    }
}

impl Error for EnrollmentDtoError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_submission_round_trips_without_changing_the_proof() {
        let credential = InstanceCredential::generate(ActorId::new());
        let dto = EnrollmentSubmissionRequest::sign(
            &credential,
            EnrollmentChallenge::from_bytes([9; 32]),
            "https://worker.example.test",
            "pod-uid",
            "secret-token".to_owned(),
        )
        .unwrap();
        let json = serde_json::to_string(&dto).unwrap();
        let restored: EnrollmentSubmissionRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(serde_json::to_string(&restored).unwrap(), json);
        let domain = restored.into_domain().unwrap();

        assert_eq!(domain.public_key(), credential.public_key());
        assert_eq!(domain.endpoint(), "https://worker.example.test");
    }

    #[test]
    fn submission_is_serializable_without_requiring_debug_output() {
        fn accepts_serialize<T: Serialize>(_: &T) {}

        let credential = InstanceCredential::generate(ActorId::new());
        let dto = EnrollmentSubmissionRequest::sign(
            &credential,
            EnrollmentChallenge::from_bytes([1; 32]),
            "https://worker.example.test",
            "pod-uid",
            "secret-token".to_owned(),
        )
        .unwrap();
        accepts_serialize(&dto);
    }

    #[test]
    fn rejects_unknown_fields_and_non_canonical_binary_encoding() {
        let unknown = format!(r#"{{"service_id":"{}","unexpected":true}}"#, ActorId::new());
        assert!(serde_json::from_str::<EnrollmentChallengeRequest>(&unknown).is_err());
        assert_eq!(
            decode_fixed::<32>("not+base64"),
            Err(EnrollmentDtoError::InvalidEncoding)
        );
    }

    #[test]
    fn error_response_never_exposes_internal_repository_details() {
        let response = EnrollmentErrorResponse::from_enrollment_error(
            &EnrollmentError::Repository("password=secret".to_owned()),
        );
        let json = serde_json::to_string(&response).unwrap();

        assert!(!json.contains("password"));
        assert!(!json.contains("secret"));
        assert_eq!(response.code, "internal_error");
    }
}
