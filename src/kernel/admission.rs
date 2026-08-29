//! Goal: enforce independently administered, default-deny communication state
//! without treating identity lifecycle or health as authorization to connect.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

use super::identity::ActorId;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommunicationAdmission {
    service_id: ActorId,
    enabled: bool,
    revision: i64,
    updated_at: i64,
}

impl CommunicationAdmission {
    pub fn restore(
        service_id: ActorId,
        enabled: bool,
        revision: i64,
        updated_at: i64,
    ) -> Result<Self, AdmissionError> {
        if revision < 0 || updated_at < 0 {
            return Err(AdmissionError::InvalidStoredRecord);
        }
        Ok(Self {
            service_id,
            enabled,
            revision,
            updated_at,
        })
    }

    pub const fn service_id(&self) -> ActorId {
        self.service_id
    }

    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub const fn revision(&self) -> i64 {
        self.revision
    }

    pub const fn updated_at(&self) -> i64 {
        self.updated_at
    }
}

pub trait AdmissionRepository: Send + Sync {
    fn find(&self, service_id: ActorId) -> Result<Option<CommunicationAdmission>, AdmissionError>;
}

#[derive(Clone)]
pub struct AdmissionService<R> {
    repository: R,
}

impl<R> AdmissionService<R>
where
    R: AdmissionRepository,
{
    pub const fn new(repository: R) -> Self {
        Self { repository }
    }

    pub fn require_enabled(
        &self,
        service_id: ActorId,
    ) -> Result<CommunicationAdmission, AdmissionError> {
        let admission = self
            .repository
            .find(service_id)?
            .ok_or(AdmissionError::UnknownService(service_id))?;
        if !admission.is_enabled() {
            return Err(AdmissionError::Disabled(service_id));
        }
        Ok(admission)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdmissionError {
    Disabled(ActorId),
    InvalidStoredRecord,
    Repository(String),
    UnknownService(ActorId),
}

impl Display for AdmissionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Disabled(id) => write!(formatter, "communication is disabled for service {id}"),
            Self::InvalidStoredRecord => {
                formatter.write_str("stored communication admission is invalid")
            }
            Self::Repository(message) => write!(formatter, "admission check failed: {message}"),
            Self::UnknownService(id) => write!(formatter, "service identity {id} was not found"),
        }
    }
}

impl Error for AdmissionError {}
