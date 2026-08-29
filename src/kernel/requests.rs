//! Goal: implement the minimum ILK-003 request contract as an immutable,
//! durable store-and-forward intent that the kernel expands into subscriber
//! destination routes.

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

use uuid::Uuid;

use super::Requirement;
use super::identity::ActorId;

pub const REQUIREMENT: Requirement = Requirement::new(
    "ILK-003",
    "Requests",
    "Governed communications are immutable requests with stable, non-reusable IDs.",
);

/// Maximum byte length of a canonical namespaced action.
pub const MAX_ACTION_NAME_LENGTH: usize = 200;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RequestId(Uuid);

impl RequestId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    pub const fn from_uuid(value: Uuid) -> Self {
        Self(value)
    }

    pub const fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

impl Default for RequestId {
    fn default() -> Self {
        Self::new()
    }
}

impl Display for RequestId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.0, formatter)
    }
}

impl FromStr for RequestId {
    type Err = RequestError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(value)
            .map(Self)
            .map_err(|_| RequestError::InvalidRequestId)
    }
}

/// A service-defined action in canonical dotted form, such as
/// `billing.invoice.submit`.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ActionName(String);

impl ActionName {
    pub fn new(value: &str) -> Result<Self, RequestError> {
        if !is_valid_action_name(value) {
            return Err(RequestError::InvalidActionName);
        }

        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for ActionName {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for ActionName {
    type Err = RequestError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

/// The minimum kernel-owned non-administrative object.
///
/// The source must come from the authenticated transport context. Construction
/// records that identity but does not itself authenticate or authorize it.
/// Concrete destinations belong to kernel-created request routes, so the source
/// neither selects nor discovers destination services.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Request {
    id: RequestId,
    source_service: ActorId,
    action: ActionName,
}

/// The digest of the complete semantic request envelope. It binds fields that
/// will be added to the minimum core, including artifact and schema metadata,
/// without making those fields mutable after acceptance.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RequestFingerprint([u8; 32]);

impl RequestFingerprint {
    pub const fn from_bytes(value: [u8; 32]) -> Self {
        Self(value)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptedRequest {
    request: Request,
    fingerprint: RequestFingerprint,
    accepted_at: i64,
}

impl AcceptedRequest {
    pub fn restore(
        request: Request,
        fingerprint: RequestFingerprint,
        accepted_at: i64,
    ) -> Result<Self, RequestError> {
        if accepted_at < 0 {
            return Err(RequestError::InvalidAcceptedAt);
        }
        Ok(Self {
            request,
            fingerprint,
            accepted_at,
        })
    }

    pub const fn request(&self) -> &Request {
        &self.request
    }

    pub const fn fingerprint(&self) -> RequestFingerprint {
        self.fingerprint
    }

    pub const fn accepted_at(&self) -> i64 {
        self.accepted_at
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RequestAcceptance {
    Accepted(AcceptedRequest),
    SafeRetry(AcceptedRequest),
}

impl RequestAcceptance {
    pub const fn record(&self) -> &AcceptedRequest {
        match self {
            Self::Accepted(record) | Self::SafeRetry(record) => record,
        }
    }

    pub const fn is_fresh(&self) -> bool {
        matches!(self, Self::Accepted(_))
    }
}

pub trait RequestRepository: Send + Sync {
    fn accept(
        &self,
        request: Request,
        fingerprint: RequestFingerprint,
    ) -> Result<RequestAcceptance, RequestError>;

    fn find(
        &self,
        source_service: ActorId,
        request_id: RequestId,
    ) -> Result<Option<AcceptedRequest>, RequestError>;
}

#[derive(Clone)]
pub struct RequestService<R> {
    repository: R,
}

impl<R> RequestService<R>
where
    R: RequestRepository,
{
    pub const fn new(repository: R) -> Self {
        Self { repository }
    }

    pub fn accept(
        &self,
        request: Request,
        fingerprint: RequestFingerprint,
    ) -> Result<RequestAcceptance, RequestError> {
        self.repository.accept(request, fingerprint)
    }

    pub fn find(
        &self,
        source_service: ActorId,
        request_id: RequestId,
    ) -> Result<Option<AcceptedRequest>, RequestError> {
        self.repository.find(source_service, request_id)
    }
}

impl Request {
    pub fn create(source_service: ActorId, action: &str) -> Result<Self, RequestError> {
        Self::restore(RequestId::new(), source_service, action)
    }

    pub fn restore(
        id: RequestId,
        source_service: ActorId,
        action: &str,
    ) -> Result<Self, RequestError> {
        Ok(Self {
            id,
            source_service,
            action: ActionName::new(action)?,
        })
    }

    pub const fn id(&self) -> RequestId {
        self.id
    }

    pub const fn source_service(&self) -> ActorId {
        self.source_service
    }

    pub const fn action(&self) -> &ActionName {
        &self.action
    }
}

fn is_valid_action_name(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_ACTION_NAME_LENGTH {
        return false;
    }

    let mut segments = value.split('.');
    let Some(namespace) = segments.next() else {
        return false;
    };
    let Some(first_action_segment) = segments.next() else {
        return false;
    };

    is_valid_action_segment(namespace)
        && is_valid_action_segment(first_action_segment)
        && segments.all(is_valid_action_segment)
}

fn is_valid_action_segment(segment: &str) -> bool {
    let mut bytes = segment.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z'))
        && bytes
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"_-".contains(&byte))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RequestError {
    InvalidRequestId,
    InvalidActionName,
    InvalidAcceptedAt,
    RequestIdConflict(RequestId),
    Repository(String),
    UnknownSource(ActorId),
}

impl Display for RequestError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequestId => formatter.write_str("request ID must be a UUID"),
            Self::InvalidActionName => formatter.write_str(
                "action must be a canonical dotted lower-case name within the length limit",
            ),
            Self::InvalidAcceptedAt => {
                formatter.write_str("request acceptance timestamp is invalid")
            }
            Self::RequestIdConflict(id) => {
                write!(formatter, "request ID {id} is bound to different content")
            }
            Self::Repository(message) => write!(formatter, "request repository failed: {message}"),
            Self::UnknownSource(id) => {
                write!(formatter, "source service identity {id} was not found")
            }
        }
    }
}

impl Error for RequestError {}

#[cfg(test)]
mod tests {
    use super::{ActionName, MAX_ACTION_NAME_LENGTH, REQUIREMENT, RequestError};

    #[test]
    fn traces_to_requests_requirement() {
        assert_eq!(REQUIREMENT.id, "ILK-003");
        assert_eq!(REQUIREMENT.capability, "Requests");
    }

    #[test]
    fn accepts_canonical_service_owned_action_names() {
        let action = ActionName::new("billing.invoice_line.submit-v2").unwrap();
        assert_eq!(action.as_str(), "billing.invoice_line.submit-v2");
    }

    #[test]
    fn rejects_non_namespaced_or_noncanonical_actions() {
        for invalid in [
            "submit",
            ".submit",
            "billing.",
            "billing..submit",
            "Billing.submit",
            "billing.Submit",
            "billing submit",
        ] {
            assert_eq!(
                ActionName::new(invalid),
                Err(RequestError::InvalidActionName)
            );
        }

        let oversized = format!("billing.{}", "a".repeat(MAX_ACTION_NAME_LENGTH));
        assert_eq!(
            ActionName::new(&oversized),
            Err(RequestError::InvalidActionName)
        );
    }
}
