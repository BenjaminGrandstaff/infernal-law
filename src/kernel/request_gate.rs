//! Goal: compose service signature verification, replay reservation, and
//! communication admission in one ordered fail-closed boundary for transports.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

use super::admission::{AdmissionError, AdmissionRepository, AdmissionService};
use super::identity::ActorId;
use super::replay_protection::{
    ReplayDisposition, ReplayProtectionError, ReplayProtectionRepository, ReplayProtectionService,
};
use super::service_requests::{
    EligibleInstanceResolver, ServiceRequestAuthenticationError, ServiceRequestVerifier,
    SignedServiceRequest, VerifiedServiceRequest,
};

pub trait SignatureVerification: Send + Sync {
    fn verify_signature(
        &self,
        request: &SignedServiceRequest,
        now: i64,
    ) -> Result<VerifiedServiceRequest, ServiceRequestAuthenticationError>;
}

impl<R> SignatureVerification for ServiceRequestVerifier<R>
where
    R: EligibleInstanceResolver,
{
    fn verify_signature(
        &self,
        request: &SignedServiceRequest,
        now: i64,
    ) -> Result<VerifiedServiceRequest, ServiceRequestAuthenticationError> {
        self.verify(request, now)
    }
}

pub trait ReplayReservation: Send + Sync {
    fn reserve_replay(
        &self,
        request: VerifiedServiceRequest,
        now: i64,
    ) -> Result<ReplayDisposition, ReplayProtectionError>;
}

impl<R> ReplayReservation for ReplayProtectionService<R>
where
    R: ReplayProtectionRepository,
{
    fn reserve_replay(
        &self,
        request: VerifiedServiceRequest,
        now: i64,
    ) -> Result<ReplayDisposition, ReplayProtectionError> {
        self.protect(request, now)
    }
}

pub trait CommunicationAdmissionCheck: Send + Sync {
    fn require_communication(&self, service_id: ActorId) -> Result<i64, AdmissionError>;
}

impl<R> CommunicationAdmissionCheck for AdmissionService<R>
where
    R: AdmissionRepository,
{
    fn require_communication(&self, service_id: ActorId) -> Result<i64, AdmissionError> {
        self.require_enabled(service_id)
            .map(|admission| admission.revision())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdmittedServiceRequest {
    verified: VerifiedServiceRequest,
    replay_disposition: ReplayDisposition,
    admission_revision: i64,
}

impl AdmittedServiceRequest {
    pub const fn verified(self) -> VerifiedServiceRequest {
        self.verified
    }

    pub const fn replay_disposition(self) -> ReplayDisposition {
        self.replay_disposition
    }

    pub const fn admission_revision(self) -> i64 {
        self.admission_revision
    }
}

#[derive(Clone)]
pub struct ServiceRequestGate<V, P, A> {
    signatures: V,
    replay: P,
    admission: A,
}

impl<V, P, A> ServiceRequestGate<V, P, A>
where
    V: SignatureVerification,
    P: ReplayReservation,
    A: CommunicationAdmissionCheck,
{
    pub const fn new(signatures: V, replay: P, admission: A) -> Self {
        Self {
            signatures,
            replay,
            admission,
        }
    }

    pub fn admit(
        &self,
        request: &SignedServiceRequest,
        now: i64,
    ) -> Result<AdmittedServiceRequest, ServiceRequestGateError> {
        let verified = self
            .signatures
            .verify_signature(request, now)
            .map_err(ServiceRequestGateError::Signature)?;
        let replay_disposition = self
            .replay
            .reserve_replay(verified, now)
            .map_err(ServiceRequestGateError::Replay)?;
        let admission_revision = self
            .admission
            .require_communication(verified.service_id())
            .map_err(ServiceRequestGateError::Admission)?;
        Ok(AdmittedServiceRequest {
            verified,
            replay_disposition,
            admission_revision,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ServiceRequestGateError {
    Admission(AdmissionError),
    Replay(ReplayProtectionError),
    Signature(ServiceRequestAuthenticationError),
}

impl Display for ServiceRequestGateError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Admission(error) => Display::fmt(error, formatter),
            Self::Replay(error) => Display::fmt(error, formatter),
            Self::Signature(error) => Display::fmt(error, formatter),
        }
    }
}

impl Error for ServiceRequestGateError {}
