//! Goal: verify the fixed signed-HTTP profile for service requests before a
//! transport can treat caller-controlled fields as authenticated context.

use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};
use std::str::FromStr;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::identity::ActorId;
use super::instance_keys::{InstanceCredential, InstanceId, InstanceSignature, KeyId};
use super::instance_registry::{
    InstanceRegistryError, InstanceRegistryRepository, InstanceRegistryService, RegisteredInstance,
};

pub const SIGNATURE_LABEL: &str = "sig1";
pub const SIGNATURE_VALIDITY_SECONDS: i64 = 30;
pub const CLOCK_SKEW_SECONDS: i64 = 5;
pub const MIN_NONCE_LENGTH: usize = 16;
pub const MAX_NONCE_LENGTH: usize = 128;

const COVERED_COMPONENTS: &str = "(\"@method\" \"@target-uri\" \"content-digest\" \"content-type\" \"infernal-service-id\" \"infernal-instance-id\" \"infernal-request-id\")";

#[derive(Clone, Eq, PartialEq)]
pub struct ServiceRequestParts {
    method: String,
    authority: String,
    path_and_query: String,
    content_type: String,
    body: Vec<u8>,
    request_id: Uuid,
}

impl Debug for ServiceRequestParts {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServiceRequestParts")
            .field("method", &self.method)
            .field("authority", &self.authority)
            .field("path_and_query", &self.path_and_query)
            .field("content_type", &self.content_type)
            .field("body", &format_args!("[{} bytes]", self.body.len()))
            .field("request_id", &self.request_id)
            .finish()
    }
}

impl ServiceRequestParts {
    pub fn new(
        method: &str,
        authority: &str,
        path_and_query: &str,
        content_type: &str,
        body: &[u8],
        request_id: Uuid,
    ) -> Result<Self, ServiceRequestAuthenticationError> {
        if method.is_empty()
            || !method.bytes().all(|byte| byte.is_ascii_uppercase())
            || !valid_uri_value(authority)
            || authority
                .bytes()
                .any(|byte| matches!(byte, b'/' | b'@' | b'?' | b'#'))
            || !path_and_query.starts_with('/')
            || path_and_query.contains('#')
            || !valid_uri_value(path_and_query)
            || !valid_header_value(content_type)
        {
            return Err(ServiceRequestAuthenticationError::Malformed);
        }
        Ok(Self {
            method: method.to_owned(),
            authority: authority.to_owned(),
            path_and_query: path_and_query.to_owned(),
            content_type: content_type.to_owned(),
            body: body.to_vec(),
            request_id,
        })
    }

    pub fn method(&self) -> &str {
        &self.method
    }

    pub fn target_uri(&self) -> String {
        format!("https://{}{}", self.authority, self.path_and_query)
    }

    pub fn content_type(&self) -> &str {
        &self.content_type
    }

    pub fn body(&self) -> &[u8] {
        &self.body
    }

    pub const fn request_id(&self) -> Uuid {
        self.request_id
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct SignedServiceRequest {
    parts: ServiceRequestParts,
    service_id: ActorId,
    instance_id: InstanceId,
    content_digest: String,
    signature_input: String,
    signature: String,
}

impl SignedServiceRequest {
    pub fn sign(
        parts: ServiceRequestParts,
        credential: &InstanceCredential,
        created: i64,
        expires: i64,
        nonce: &str,
    ) -> Result<Self, ServiceRequestAuthenticationError> {
        validate_signature_metadata(created, expires, nonce)?;
        let public_key = credential.public_key();
        let content_digest = content_digest(parts.body());
        let signature_parameters =
            signature_parameters(created, expires, nonce, public_key.key_id());
        let base = signature_base(
            &parts,
            public_key.service_id(),
            public_key.instance_id(),
            &content_digest,
            &signature_parameters,
        );
        let signature = credential.sign(base.as_bytes());
        Ok(Self {
            parts,
            service_id: public_key.service_id(),
            instance_id: public_key.instance_id(),
            content_digest,
            signature_input: format!("{SIGNATURE_LABEL}={signature_parameters}"),
            signature: format!(
                "{SIGNATURE_LABEL}=:{}:",
                STANDARD.encode(signature.as_bytes())
            ),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_wire(
        parts: ServiceRequestParts,
        service_id: &str,
        instance_id: &str,
        content_digest: &str,
        signature_input: &str,
        signature: &str,
    ) -> Result<Self, ServiceRequestAuthenticationError> {
        Ok(Self {
            parts,
            service_id: service_id
                .parse()
                .map_err(|_| ServiceRequestAuthenticationError::Malformed)?,
            instance_id: instance_id
                .parse()
                .map_err(|_| ServiceRequestAuthenticationError::Malformed)?,
            content_digest: content_digest.to_owned(),
            signature_input: signature_input.to_owned(),
            signature: signature.to_owned(),
        })
    }

    pub const fn parts(&self) -> &ServiceRequestParts {
        &self.parts
    }

    pub const fn service_id(&self) -> ActorId {
        self.service_id
    }

    pub const fn instance_id(&self) -> InstanceId {
        self.instance_id
    }

    pub fn content_digest(&self) -> &str {
        &self.content_digest
    }

    pub fn signature_input(&self) -> &str {
        &self.signature_input
    }

    pub fn signature(&self) -> &str {
        &self.signature
    }
}

impl Debug for SignedServiceRequest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedServiceRequest")
            .field("parts", &self.parts)
            .field("service_id", &self.service_id)
            .field("instance_id", &self.instance_id)
            .field("content_digest", &self.content_digest)
            .field("signature_input", &self.signature_input)
            .field("signature", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedServiceRequest {
    service_id: ActorId,
    instance_id: InstanceId,
    key_id: KeyId,
    request_id: Uuid,
    created: i64,
    expires: i64,
    nonce_digest: [u8; 32],
    request_fingerprint: [u8; 32],
}

impl VerifiedServiceRequest {
    pub const fn service_id(self) -> ActorId {
        self.service_id
    }

    pub const fn instance_id(self) -> InstanceId {
        self.instance_id
    }

    pub const fn key_id(self) -> KeyId {
        self.key_id
    }

    pub const fn request_id(self) -> Uuid {
        self.request_id
    }

    pub const fn created(self) -> i64 {
        self.created
    }

    pub const fn expires(self) -> i64 {
        self.expires
    }

    pub const fn nonce_digest(self) -> [u8; 32] {
        self.nonce_digest
    }

    pub const fn request_fingerprint(self) -> [u8; 32] {
        self.request_fingerprint
    }
}

pub trait EligibleInstanceResolver: Send + Sync {
    fn find_eligible(
        &self,
        instance_id: InstanceId,
        now: i64,
    ) -> Result<RegisteredInstance, InstanceRegistryError>;
}

impl<R> EligibleInstanceResolver for InstanceRegistryService<R>
where
    R: InstanceRegistryRepository,
{
    fn find_eligible(
        &self,
        instance_id: InstanceId,
        now: i64,
    ) -> Result<RegisteredInstance, InstanceRegistryError> {
        InstanceRegistryService::find_eligible(self, instance_id, now)
    }
}

#[derive(Clone)]
pub struct ServiceRequestVerifier<R> {
    instances: R,
}

impl<R> ServiceRequestVerifier<R>
where
    R: EligibleInstanceResolver,
{
    pub const fn new(instances: R) -> Self {
        Self { instances }
    }

    pub fn verify(
        &self,
        request: &SignedServiceRequest,
        now: i64,
    ) -> Result<VerifiedServiceRequest, ServiceRequestAuthenticationError> {
        let metadata = parse_signature_input(request.signature_input())?;
        validate_signature_time(metadata.created, metadata.expires, now)?;

        let instance = self
            .instances
            .find_eligible(request.instance_id(), now)
            .map_err(ServiceRequestAuthenticationError::Registry)?;
        let public_key = instance.public_key();
        if public_key.service_id() != request.service_id()
            || public_key.instance_id() != request.instance_id()
            || public_key.key_id() != metadata.key_id
        {
            return Err(ServiceRequestAuthenticationError::CredentialMismatch);
        }
        verify_content_digest(request.parts().body(), request.content_digest())?;

        let signature = parse_signature(request.signature())?;
        let base = signature_base(
            request.parts(),
            request.service_id(),
            request.instance_id(),
            request.content_digest(),
            &metadata.parameters,
        );
        public_key
            .verify(base.as_bytes(), &signature)
            .map_err(|_| ServiceRequestAuthenticationError::InvalidSignature)?;

        Ok(VerifiedServiceRequest {
            service_id: request.service_id(),
            instance_id: request.instance_id(),
            key_id: metadata.key_id,
            request_id: request.parts().request_id(),
            created: metadata.created,
            expires: metadata.expires,
            nonce_digest: Sha256::digest(metadata.nonce.as_bytes()).into(),
            request_fingerprint: request_fingerprint(request),
        })
    }
}

struct SignatureMetadata {
    parameters: String,
    created: i64,
    expires: i64,
    nonce: String,
    key_id: KeyId,
}

fn signature_parameters(created: i64, expires: i64, nonce: &str, key_id: KeyId) -> String {
    format!(
        "{COVERED_COMPONENTS};created={created};expires={expires};nonce=\"{nonce}\";keyid=\"{key_id}\";alg=\"ed25519\""
    )
}

fn parse_signature_input(
    value: &str,
) -> Result<SignatureMetadata, ServiceRequestAuthenticationError> {
    let parameters = value
        .strip_prefix(&format!("{SIGNATURE_LABEL}="))
        .ok_or(ServiceRequestAuthenticationError::Malformed)?;
    let remainder = parameters
        .strip_prefix(COVERED_COMPONENTS)
        .and_then(|value| value.strip_prefix(";created="))
        .ok_or(ServiceRequestAuthenticationError::Malformed)?;
    let (created, remainder) = remainder
        .split_once(";expires=")
        .ok_or(ServiceRequestAuthenticationError::Malformed)?;
    let (expires, remainder) = remainder
        .split_once(";nonce=\"")
        .ok_or(ServiceRequestAuthenticationError::Malformed)?;
    let (nonce, remainder) = remainder
        .split_once("\";keyid=\"")
        .ok_or(ServiceRequestAuthenticationError::Malformed)?;
    let (key_id, algorithm) = remainder
        .split_once("\";alg=\"")
        .ok_or(ServiceRequestAuthenticationError::Malformed)?;
    if algorithm != "ed25519\"" {
        return Err(ServiceRequestAuthenticationError::Malformed);
    }
    let created = parse_timestamp(created)?;
    let expires = parse_timestamp(expires)?;
    validate_signature_metadata(created, expires, nonce)?;
    let key_id =
        KeyId::from_str(key_id).map_err(|_| ServiceRequestAuthenticationError::Malformed)?;
    Ok(SignatureMetadata {
        parameters: parameters.to_owned(),
        created,
        expires,
        nonce: nonce.to_owned(),
        key_id,
    })
}

fn parse_signature(value: &str) -> Result<InstanceSignature, ServiceRequestAuthenticationError> {
    let encoded = value
        .strip_prefix(&format!("{SIGNATURE_LABEL}=:"))
        .and_then(|value| value.strip_suffix(':'))
        .ok_or(ServiceRequestAuthenticationError::Malformed)?;
    let bytes = STANDARD
        .decode(encoded)
        .map_err(|_| ServiceRequestAuthenticationError::Malformed)?;
    let bytes: [u8; 64] = bytes
        .try_into()
        .map_err(|_| ServiceRequestAuthenticationError::Malformed)?;
    if STANDARD.encode(bytes) != encoded {
        return Err(ServiceRequestAuthenticationError::Malformed);
    }
    Ok(InstanceSignature::from_bytes(bytes))
}

fn signature_base(
    parts: &ServiceRequestParts,
    service_id: ActorId,
    instance_id: InstanceId,
    digest: &str,
    parameters: &str,
) -> String {
    format!(
        "\"@method\": {}\n\"@target-uri\": {}\n\"content-digest\": {}\n\"content-type\": {}\n\"infernal-service-id\": {}\n\"infernal-instance-id\": {}\n\"infernal-request-id\": {}\n\"@signature-params\": {}",
        parts.method(),
        parts.target_uri(),
        digest,
        parts.content_type(),
        service_id,
        instance_id,
        parts.request_id(),
        parameters,
    )
}

fn content_digest(body: &[u8]) -> String {
    format!("sha-256=:{}:", STANDARD.encode(Sha256::digest(body)))
}

fn request_fingerprint(request: &SignedServiceRequest) -> [u8; 32] {
    Sha256::digest(
        format!(
            "\"@method\": {}\n\"@target-uri\": {}\n\"content-digest\": {}\n\"content-type\": {}\n\"infernal-service-id\": {}",
            request.parts().method(),
            request.parts().target_uri(),
            request.content_digest(),
            request.parts().content_type(),
            request.service_id(),
        )
        .as_bytes(),
    )
    .into()
}

fn verify_content_digest(
    body: &[u8],
    supplied: &str,
) -> Result<(), ServiceRequestAuthenticationError> {
    if content_digest(body) == supplied {
        Ok(())
    } else {
        Err(ServiceRequestAuthenticationError::InvalidContentDigest)
    }
}

fn validate_signature_metadata(
    created: i64,
    expires: i64,
    nonce: &str,
) -> Result<(), ServiceRequestAuthenticationError> {
    if created < 0
        || expires <= created
        || expires - created > SIGNATURE_VALIDITY_SECONDS
        || !(MIN_NONCE_LENGTH..=MAX_NONCE_LENGTH).contains(&nonce.len())
        || !nonce
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(ServiceRequestAuthenticationError::Malformed);
    }
    Ok(())
}

fn validate_signature_time(
    created: i64,
    expires: i64,
    now: i64,
) -> Result<(), ServiceRequestAuthenticationError> {
    if now < 0
        || created > now.saturating_add(CLOCK_SKEW_SECONDS)
        || expires.saturating_add(CLOCK_SKEW_SECONDS) < now
    {
        return Err(ServiceRequestAuthenticationError::NotFresh);
    }
    Ok(())
}

fn parse_timestamp(value: &str) -> Result<i64, ServiceRequestAuthenticationError> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ServiceRequestAuthenticationError::Malformed);
    }
    value
        .parse()
        .map_err(|_| ServiceRequestAuthenticationError::Malformed)
}

fn valid_header_value(value: &str) -> bool {
    !value.is_empty()
        && value.trim() == value
        && value.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
}

fn valid_uri_value(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ServiceRequestAuthenticationError {
    CredentialMismatch,
    InvalidContentDigest,
    InvalidSignature,
    Malformed,
    NotFresh,
    Registry(InstanceRegistryError),
}

impl Display for ServiceRequestAuthenticationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::CredentialMismatch => formatter.write_str("request credential does not match"),
            Self::InvalidContentDigest => formatter.write_str("request content digest is invalid"),
            Self::InvalidSignature => formatter.write_str("request signature is invalid"),
            Self::Malformed => formatter.write_str("signed request is malformed"),
            Self::NotFresh => formatter.write_str("request signature is not fresh"),
            Self::Registry(error) => write!(formatter, "request key lookup failed: {error}"),
        }
    }
}

impl Error for ServiceRequestAuthenticationError {}
