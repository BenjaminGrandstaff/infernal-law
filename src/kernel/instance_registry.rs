//! Goal: manage kernel-owned public instance keys and bounded leases through
//! typed contracts without exposing SQL or persisting private keys.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

use crate::kernel::identity::ActorId;
use crate::kernel::instance_keys::{InstanceId, InstanceKeyError, InstancePublicKey};

pub const DEFAULT_LEASE_SECONDS: i64 = 60;
pub const MAX_LEASE_SECONDS: i64 = 300;
pub const MAX_ENDPOINT_LENGTH: usize = 2048;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LeasePolicy {
    duration_seconds: i64,
}

impl LeasePolicy {
    pub fn new(duration_seconds: i64) -> Result<Self, InstanceRegistryError> {
        if !(1..=MAX_LEASE_SECONDS).contains(&duration_seconds) {
            return Err(InstanceRegistryError::InvalidLeaseDuration);
        }
        Ok(Self { duration_seconds })
    }

    pub const fn duration_seconds(self) -> i64 {
        self.duration_seconds
    }
}

impl Default for LeasePolicy {
    fn default() -> Self {
        Self {
            duration_seconds: DEFAULT_LEASE_SECONDS,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegisteredInstance {
    public_key: InstancePublicKey,
    endpoint: String,
    registered_at: i64,
    lease_expires_at: i64,
    lease_revision: i64,
    revoked_at: Option<i64>,
}

impl RegisteredInstance {
    pub fn create(
        public_key: InstancePublicKey,
        endpoint: &str,
        registered_at: i64,
        lease_expires_at: i64,
    ) -> Result<Self, InstanceRegistryError> {
        Self::restore(
            public_key,
            endpoint,
            registered_at,
            lease_expires_at,
            1,
            None,
        )
    }

    pub fn restore(
        public_key: InstancePublicKey,
        endpoint: &str,
        registered_at: i64,
        lease_expires_at: i64,
        lease_revision: i64,
        revoked_at: Option<i64>,
    ) -> Result<Self, InstanceRegistryError> {
        let endpoint = validate_endpoint(endpoint)?;
        if registered_at < 0
            || lease_expires_at <= registered_at
            || lease_revision <= 0
            || revoked_at.is_some_and(|value| value < registered_at)
        {
            return Err(InstanceRegistryError::InvalidStoredRecord);
        }
        Ok(Self {
            public_key,
            endpoint,
            registered_at,
            lease_expires_at,
            lease_revision,
            revoked_at,
        })
    }

    pub const fn public_key(&self) -> &InstancePublicKey {
        &self.public_key
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub const fn registered_at(&self) -> i64 {
        self.registered_at
    }

    pub const fn lease_expires_at(&self) -> i64 {
        self.lease_expires_at
    }

    pub const fn lease_revision(&self) -> i64 {
        self.lease_revision
    }

    pub const fn revoked_at(&self) -> Option<i64> {
        self.revoked_at
    }

    pub fn is_eligible_at(&self, now: i64) -> bool {
        self.revoked_at.is_none() && now >= self.registered_at && now < self.lease_expires_at
    }
}

fn validate_endpoint(endpoint: &str) -> Result<String, InstanceRegistryError> {
    let endpoint = endpoint.trim();
    if !endpoint.starts_with("https://")
        || endpoint.len() > MAX_ENDPOINT_LENGTH
        || endpoint.len() == "https://".len()
    {
        return Err(InstanceRegistryError::InvalidEndpoint);
    }
    Ok(endpoint.to_owned())
}

pub trait InstanceRegistryRepository: Send + Sync {
    fn insert(&self, instance: RegisteredInstance) -> Result<(), InstanceRegistryError>;
    fn find(
        &self,
        instance_id: InstanceId,
    ) -> Result<Option<RegisteredInstance>, InstanceRegistryError>;
    fn renew(
        &self,
        instance_id: InstanceId,
        expected_revision: i64,
        renewed_at: i64,
        lease_expires_at: i64,
    ) -> Result<RegisteredInstance, InstanceRegistryError>;
    fn revoke(
        &self,
        instance_id: InstanceId,
        revoked_at: i64,
    ) -> Result<RegisteredInstance, InstanceRegistryError>;
}

#[derive(Clone)]
pub struct InstanceRegistryService<R> {
    repository: R,
    lease_policy: LeasePolicy,
}

impl<R> InstanceRegistryService<R>
where
    R: InstanceRegistryRepository,
{
    pub const fn new(repository: R, lease_policy: LeasePolicy) -> Self {
        Self {
            repository,
            lease_policy,
        }
    }

    pub fn register_verified(
        &self,
        public_key: InstancePublicKey,
        endpoint: &str,
        now: i64,
    ) -> Result<RegisteredInstance, InstanceRegistryError> {
        validate_timestamp(now)?;
        let expires_at = now
            .checked_add(self.lease_policy.duration_seconds())
            .ok_or(InstanceRegistryError::InvalidTimestamp)?;
        let instance = RegisteredInstance::create(public_key, endpoint, now, expires_at)?;
        self.repository.insert(instance.clone())?;
        Ok(instance)
    }

    pub fn find_eligible(
        &self,
        instance_id: InstanceId,
        now: i64,
    ) -> Result<RegisteredInstance, InstanceRegistryError> {
        validate_timestamp(now)?;
        let instance = self
            .repository
            .find(instance_id)?
            .ok_or(InstanceRegistryError::NotFound(instance_id))?;
        if instance.revoked_at().is_some() {
            return Err(InstanceRegistryError::Revoked(instance_id));
        }
        if !instance.is_eligible_at(now) {
            return Err(InstanceRegistryError::Expired(instance_id));
        }
        Ok(instance)
    }

    pub fn renew(
        &self,
        instance_id: InstanceId,
        expected_revision: i64,
        now: i64,
    ) -> Result<RegisteredInstance, InstanceRegistryError> {
        validate_timestamp(now)?;
        if expected_revision <= 0 {
            return Err(InstanceRegistryError::RevisionConflict(instance_id));
        }
        let expires_at = now
            .checked_add(self.lease_policy.duration_seconds())
            .ok_or(InstanceRegistryError::InvalidTimestamp)?;
        self.repository
            .renew(instance_id, expected_revision, now, expires_at)
    }

    pub fn revoke(
        &self,
        instance_id: InstanceId,
        now: i64,
    ) -> Result<RegisteredInstance, InstanceRegistryError> {
        validate_timestamp(now)?;
        self.repository.revoke(instance_id, now)
    }
}

fn validate_timestamp(timestamp: i64) -> Result<(), InstanceRegistryError> {
    if timestamp < 0 {
        return Err(InstanceRegistryError::InvalidTimestamp);
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InstanceRegistryError {
    AlreadyExists(InstanceId),
    Expired(InstanceId),
    InvalidEndpoint,
    InvalidLeaseDuration,
    InvalidStoredRecord,
    InvalidTimestamp,
    Key(InstanceKeyError),
    NotFound(InstanceId),
    Repository(String),
    RevisionConflict(InstanceId),
    Revoked(InstanceId),
    UnknownService(ActorId),
}

impl Display for InstanceRegistryError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyExists(id) => write!(formatter, "service instance {id} already exists"),
            Self::Expired(id) => write!(formatter, "service instance {id} lease has expired"),
            Self::InvalidEndpoint => formatter
                .write_str("instance endpoint must use HTTPS and contain at most 2048 bytes"),
            Self::InvalidLeaseDuration => write!(
                formatter,
                "lease duration must be between 1 and {MAX_LEASE_SECONDS} seconds"
            ),
            Self::InvalidStoredRecord => {
                formatter.write_str("stored service instance record is invalid")
            }
            Self::InvalidTimestamp => formatter.write_str("instance timestamp is invalid"),
            Self::Key(error) => Display::fmt(error, formatter),
            Self::NotFound(id) => write!(formatter, "service instance {id} was not found"),
            Self::Repository(message) => write!(formatter, "instance registry failed: {message}"),
            Self::RevisionConflict(id) => {
                write!(formatter, "service instance {id} lease revision conflicts")
            }
            Self::Revoked(id) => write!(formatter, "service instance {id} is revoked"),
            Self::UnknownService(id) => write!(formatter, "service identity {id} was not found"),
        }
    }
}

impl Error for InstanceRegistryError {}

impl From<InstanceKeyError> for InstanceRegistryError {
    fn from(value: InstanceKeyError) -> Self {
        Self::Key(value)
    }
}
