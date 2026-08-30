//! Goal: implement the minimum ILK-003 request contract as an immutable,
//! durable store-and-forward intent that the kernel expands into subscriber
//! destination routes.

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::Requirement;
use super::authority::{SchemaVersionRefs, Scope};
use super::identity::ActorId;
use super::subscriptions::SubscriptionId;

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
///
/// `scope` and `schema_versions` are the same artifact descriptor and
/// permission-policy schema reference ILK-002 authority evaluates the
/// request against (`PolicyFacts::for_request_acceptance`) -- ILK-003
/// requires them on every request, and reusing `authority::Scope`/
/// `SchemaVersionRefs` here means there is exactly one validated
/// representation of each, not a parallel one that could drift.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Request {
    id: RequestId,
    source_service: ActorId,
    action: ActionName,
    scope: Scope,
    schema_versions: SchemaVersionRefs,
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

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RouteId(Uuid);

impl RouteId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    pub const fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

impl Default for RouteId {
    fn default() -> Self {
        Self::new()
    }
}

impl Display for RouteId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.0, formatter)
    }
}

impl FromStr for RouteId {
    type Err = RequestError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(value)
            .map(Self)
            .map_err(|_| RequestError::InvalidRouteId)
    }
}

/// An independent destination the kernel materialized for an accepted
/// request, because some active inclusive subscription matched it
/// (ILK-010). One request may have many routes, one per matching
/// subscription; each is materialized at most once, keyed by
/// `(request_id, subscription_id)` -- repeated scans, wakeups, or retries
/// of the same match never create a second route. This is deliberately the
/// minimum slice: no delivery state, transition history, or work claim yet
/// (ILK-011) -- a route here records only that a destination is eligible,
/// nothing about whether it has been worked.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Route {
    id: RouteId,
    source_service: ActorId,
    request_id: RequestId,
    subscription_id: SubscriptionId,
    destination_service: ActorId,
    created_at: i64,
}

impl Route {
    pub fn create(
        source_service: ActorId,
        request_id: RequestId,
        subscription_id: SubscriptionId,
        destination_service: ActorId,
        created_at: i64,
    ) -> Result<Self, RequestError> {
        Self::restore(
            RouteId::new(),
            source_service,
            request_id,
            subscription_id,
            destination_service,
            created_at,
        )
    }

    pub fn restore(
        id: RouteId,
        source_service: ActorId,
        request_id: RequestId,
        subscription_id: SubscriptionId,
        destination_service: ActorId,
        created_at: i64,
    ) -> Result<Self, RequestError> {
        if created_at < 0 {
            return Err(RequestError::InvalidAcceptedAt);
        }
        Ok(Self {
            id,
            source_service,
            request_id,
            subscription_id,
            destination_service,
            created_at,
        })
    }

    pub const fn id(&self) -> RouteId {
        self.id
    }

    pub const fn source_service(&self) -> ActorId {
        self.source_service
    }

    pub const fn request_id(&self) -> RequestId {
        self.request_id
    }

    pub const fn subscription_id(&self) -> SubscriptionId {
        self.subscription_id
    }

    pub const fn destination_service(&self) -> ActorId {
        self.destination_service
    }

    pub const fn created_at(&self) -> i64 {
        self.created_at
    }
}

pub trait RouteRepository: Send + Sync {
    /// Idempotently materializes `route`. If a route already exists for
    /// `(request_id, subscription_id)`, returns that existing route
    /// unchanged rather than creating a second one -- this is what makes
    /// repeated matching scans, subscription wakeups, and retries safe.
    fn materialize(&self, route: Route) -> Result<Route, RequestError>;

    fn list_for_request(&self, request_id: RequestId) -> Result<Vec<Route>, RequestError>;

    /// Lists every route currently materialized for `destination_service`,
    /// in creation order -- the read an eligible-route query (ADR-0011)
    /// composes with ILK-011's active-claim check to find claimable work.
    fn list_for_destination(
        &self,
        destination_service: ActorId,
    ) -> Result<Vec<Route>, RequestError>;
}

#[derive(Clone)]
pub struct RouteService<R> {
    repository: R,
}

impl<R> RouteService<R>
where
    R: RouteRepository,
{
    pub const fn new(repository: R) -> Self {
        Self { repository }
    }

    pub fn materialize(
        &self,
        source_service: ActorId,
        request_id: RequestId,
        subscription_id: SubscriptionId,
        destination_service: ActorId,
        now: i64,
    ) -> Result<Route, RequestError> {
        let route = Route::create(
            source_service,
            request_id,
            subscription_id,
            destination_service,
            now,
        )?;
        self.repository.materialize(route)
    }

    pub fn list_for_request(&self, request_id: RequestId) -> Result<Vec<Route>, RequestError> {
        self.repository.list_for_request(request_id)
    }

    pub fn list_for_destination(
        &self,
        destination_service: ActorId,
    ) -> Result<Vec<Route>, RequestError> {
        self.repository.list_for_destination(destination_service)
    }
}

impl Request {
    pub fn create(
        source_service: ActorId,
        action: &str,
        scope: Scope,
        schema_versions: SchemaVersionRefs,
    ) -> Result<Self, RequestError> {
        Self::restore(
            RequestId::new(),
            source_service,
            action,
            scope,
            schema_versions,
        )
    }

    pub fn restore(
        id: RequestId,
        source_service: ActorId,
        action: &str,
        scope: Scope,
        schema_versions: SchemaVersionRefs,
    ) -> Result<Self, RequestError> {
        Ok(Self {
            id,
            source_service,
            action: ActionName::new(action)?,
            scope,
            schema_versions,
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

    pub const fn scope(&self) -> &Scope {
        &self.scope
    }

    pub const fn schema_versions(&self) -> SchemaVersionRefs {
        self.schema_versions
    }

    /// Deterministically computes this request's semantic fingerprint from
    /// its own immutable fields. Two `Request`s with identical source,
    /// action, scope, and schema versions always fingerprint identically;
    /// any difference changes it, so `RequestRepository::accept` can tell a
    /// safe retry of the same semantic request from an attempt to rebind
    /// its ID to different content. Fields are length-prefixed before
    /// hashing so no combination of values can collide by concatenation.
    pub fn fingerprint(&self) -> RequestFingerprint {
        let mut hasher = Sha256::new();
        hasher.update(self.source_service.as_uuid().as_bytes());
        hash_field(&mut hasher, self.action.as_str().as_bytes());
        hash_field(&mut hasher, self.scope.as_str().as_bytes());
        hasher.update(self.schema_versions.artifact().as_uuid().as_bytes());
        hasher.update(
            self.schema_versions
                .permission_policy()
                .as_uuid()
                .as_bytes(),
        );
        RequestFingerprint::from_bytes(hasher.finalize().into())
    }
}

fn hash_field(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
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
    InvalidRouteId,
    RequestIdConflict(RequestId),
    Repository(String),
    UnknownSource(ActorId),
    UnknownSchemaVersion,
    UnknownSubscription,
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
            Self::InvalidRouteId => formatter.write_str("route ID must be a UUID"),
            Self::RequestIdConflict(id) => {
                write!(formatter, "request ID {id} is bound to different content")
            }
            Self::Repository(message) => write!(formatter, "request repository failed: {message}"),
            Self::UnknownSource(id) => {
                write!(formatter, "source service identity {id} was not found")
            }
            Self::UnknownSchemaVersion => {
                formatter.write_str("referenced schema version was not found")
            }
            Self::UnknownSubscription => {
                formatter.write_str("referenced subscription was not found")
            }
        }
    }
}

impl Error for RequestError {}

#[cfg(test)]
mod tests {
    use super::{ActionName, MAX_ACTION_NAME_LENGTH, REQUIREMENT, Request, RequestError};
    use crate::kernel::authority::{SchemaVersionId, SchemaVersionRefs, Scope};
    use crate::kernel::identity::ActorId;

    fn schema_versions() -> SchemaVersionRefs {
        SchemaVersionRefs::new(SchemaVersionId::new(), SchemaVersionId::new())
    }

    fn request(source: ActorId, action: &str, scope: &str, versions: SchemaVersionRefs) -> Request {
        Request::create(source, action, Scope::new(scope).unwrap(), versions).unwrap()
    }

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

    #[test]
    fn fingerprint_is_deterministic_for_identical_content() {
        let source = ActorId::new();
        let versions = schema_versions();
        let first = request(source, "billing.invoice.submit", "invoice-1", versions);
        let second = request(source, "billing.invoice.submit", "invoice-1", versions);

        assert_eq!(first.fingerprint(), second.fingerprint());
    }

    #[test]
    fn fingerprint_changes_with_the_action() {
        let source = ActorId::new();
        let versions = schema_versions();
        let first = request(source, "billing.invoice.submit", "invoice-1", versions);
        let second = request(source, "billing.invoice.cancel", "invoice-1", versions);

        assert_ne!(first.fingerprint(), second.fingerprint());
    }

    #[test]
    fn fingerprint_changes_with_the_scope() {
        let source = ActorId::new();
        let versions = schema_versions();
        let first = request(source, "billing.invoice.submit", "invoice-1", versions);
        let second = request(source, "billing.invoice.submit", "invoice-2", versions);

        assert_ne!(first.fingerprint(), second.fingerprint());
    }

    #[test]
    fn fingerprint_changes_with_the_schema_versions() {
        let source = ActorId::new();
        let first = request(
            source,
            "billing.invoice.submit",
            "invoice-1",
            schema_versions(),
        );
        let second = request(
            source,
            "billing.invoice.submit",
            "invoice-1",
            schema_versions(),
        );

        assert_ne!(first.fingerprint(), second.fingerprint());
    }

    #[test]
    fn fingerprint_changes_with_the_source() {
        let versions = schema_versions();
        let first = request(
            ActorId::new(),
            "billing.invoice.submit",
            "invoice-1",
            versions,
        );
        let second = request(
            ActorId::new(),
            "billing.invoice.submit",
            "invoice-1",
            versions,
        );

        assert_ne!(first.fingerprint(), second.fingerprint());
    }

    #[test]
    fn fingerprint_cannot_be_confused_by_concatenation_across_field_boundaries() {
        let source = ActorId::new();
        let versions = schema_versions();
        let first = request(source, "billing.ab", "cd", versions);
        let second = request(source, "billing.a", "bcd", versions);

        assert_ne!(first.fingerprint(), second.fingerprint());
    }
}
