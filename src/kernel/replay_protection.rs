//! Goal: atomically consume signed-request nonces and bind stable request IDs
//! to semantic request fingerprints without conflating safe retries with replay.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

use uuid::Uuid;

use super::identity::ActorId;
use super::instance_keys::{InstanceId, KeyId};
use super::service_requests::{CLOCK_SKEW_SECONDS, VerifiedServiceRequest};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayReservation {
    service_id: ActorId,
    instance_id: InstanceId,
    key_id: KeyId,
    request_id: Uuid,
    nonce_digest: [u8; 32],
    request_fingerprint: [u8; 32],
    signature_created: i64,
    signature_expires: i64,
    reserved_at: i64,
}

impl ReplayReservation {
    pub fn from_verified(
        request: VerifiedServiceRequest,
        reserved_at: i64,
    ) -> Result<Self, ReplayProtectionError> {
        if reserved_at < 0
            || request.created() > reserved_at.saturating_add(CLOCK_SKEW_SECONDS)
            || request.expires().saturating_add(CLOCK_SKEW_SECONDS) < reserved_at
        {
            return Err(ReplayProtectionError::InvalidTimestamp);
        }
        Ok(Self {
            service_id: request.service_id(),
            instance_id: request.instance_id(),
            key_id: request.key_id(),
            request_id: request.request_id(),
            nonce_digest: request.nonce_digest(),
            request_fingerprint: request.request_fingerprint(),
            signature_created: request.created(),
            signature_expires: request.expires(),
            reserved_at,
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

    pub const fn request_id(&self) -> Uuid {
        self.request_id
    }

    pub const fn nonce_digest(&self) -> &[u8; 32] {
        &self.nonce_digest
    }

    pub const fn request_fingerprint(&self) -> &[u8; 32] {
        &self.request_fingerprint
    }

    pub const fn signature_created(&self) -> i64 {
        self.signature_created
    }

    pub const fn signature_expires(&self) -> i64 {
        self.signature_expires
    }

    pub const fn reserved_at(&self) -> i64 {
        self.reserved_at
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayDisposition {
    Fresh,
    SafeRetry,
}

pub trait ReplayProtectionRepository: Send + Sync {
    fn reserve(
        &self,
        reservation: ReplayReservation,
    ) -> Result<ReplayDisposition, ReplayProtectionError>;
}

#[derive(Clone)]
pub struct ReplayProtectionService<R> {
    repository: R,
}

impl<R> ReplayProtectionService<R>
where
    R: ReplayProtectionRepository,
{
    pub const fn new(repository: R) -> Self {
        Self { repository }
    }

    pub fn protect(
        &self,
        request: VerifiedServiceRequest,
        now: i64,
    ) -> Result<ReplayDisposition, ReplayProtectionError> {
        self.repository
            .reserve(ReplayReservation::from_verified(request, now)?)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReplayProtectionError {
    InvalidTimestamp,
    ReplayDetected,
    RequestIdConflict,
    Repository(String),
}

impl Display for ReplayProtectionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTimestamp => formatter.write_str("replay reservation time is invalid"),
            Self::ReplayDetected => formatter.write_str("request nonce was already consumed"),
            Self::RequestIdConflict => {
                formatter.write_str("request ID was already bound to different content")
            }
            Self::Repository(message) => write!(formatter, "replay protection failed: {message}"),
        }
    }
}

impl Error for ReplayProtectionError {}
