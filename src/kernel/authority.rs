//! Goal: implement ILK-002 as kernel-owned facts, grants, and pinned
//! decisions, with the allow/deny algorithm delegated to a swappable,
//! stateless policy evaluator that stores no authorization data of its own
//! (ADR-0013).

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

use uuid::Uuid;

use super::Requirement;
use super::identity::ActorId;
use super::requests::ActionName;

pub const REQUIREMENT: Requirement = Requirement::new(
    "ILK-002",
    "Authority",
    "The kernel decides whether an identity may perform an operation.",
);

/// Maximum byte length of a declared artifact/scope identifier.
pub const MAX_SCOPE_LENGTH: usize = 200;

/// Maximum byte length of a policy bundle/version identifier.
pub const MAX_POLICY_BUNDLE_VERSION_LENGTH: usize = 200;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct GrantId(Uuid);

impl GrantId {
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

impl Default for GrantId {
    fn default() -> Self {
        Self::new()
    }
}

impl Display for GrantId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.0, formatter)
    }
}

impl FromStr for GrantId {
    type Err = AuthorityError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(value)
            .map(Self)
            .map_err(|_| AuthorityError::InvalidGrantId)
    }
}

/// A declared artifact or scope identifier a grant applies to, or the
/// wildcard that matches any scope.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Scope(String);

impl Scope {
    pub fn new(value: &str) -> Result<Self, AuthorityError> {
        if value.is_empty() || value.len() > MAX_SCOPE_LENGTH || value.trim() != value {
            return Err(AuthorityError::InvalidScope);
        }
        Ok(Self(value.to_owned()))
    }

    pub fn wildcard() -> Self {
        Self("*".to_owned())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn matches(&self, requested: &Self) -> bool {
        self.0 == "*" || self.0 == requested.0
    }
}

/// The policy bundle/version an evaluator reports it evaluated against.
/// Absent from a decision only when the evaluator could not be reached
/// (ADR-0013): a decision never claims a bundle version it did not receive.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct PolicyBundleVersion(String);

impl PolicyBundleVersion {
    pub fn new(value: &str) -> Result<Self, AuthorityError> {
        if value.is_empty() || value.len() > MAX_POLICY_BUNDLE_VERSION_LENGTH {
            return Err(AuthorityError::InvalidPolicyBundleVersion);
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The two schema versions ILK-002 requires for every authority decision:
/// the artifact's own schema, and the permission-policy schema describing
/// what actions/fields are meaningful for it. Both are mandatory on every
/// [`PolicyFacts`] and every [`Grant`] — there is no partial state where a
/// grant applies without a specific version of each pinned down.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SchemaVersionRefs {
    artifact: SchemaVersionId,
    permission_policy: SchemaVersionId,
}

impl SchemaVersionRefs {
    pub const fn new(artifact: SchemaVersionId, permission_policy: SchemaVersionId) -> Self {
        Self {
            artifact,
            permission_policy,
        }
    }

    pub const fn artifact(&self) -> SchemaVersionId {
        self.artifact
    }

    pub const fn permission_policy(&self) -> SchemaVersionId {
        self.permission_policy
    }
}

/// Reserved schema-version pair for governed actions that authorize
/// administrative kernel state rather than artifact content -- for example
/// ILK-010 subscription management, which has no artifact type or content
/// to pin a real schema version to. `SchemaVersionRefs` never allows an
/// absent version (mandatory-both, not optional), so an action with no real
/// artifact still needs *some* value to reference; these fixed IDs are that
/// value, used consistently by every non-artifact-bearing fact and by any
/// grant meant to authorize such actions, rather than a fabricated one-off
/// ID per call site.
///
/// These constants intentionally do not correspond to a row anyone has to
/// publish out of band: `SchemaService::publish` is now reachable over HTTP
/// (`POST /v1/authority/schemas`), and every authority table's actor
/// columns are `NOT NULL` foreign keys into `identities` -- including
/// `service_instances.service_id`, which every enrolled instance is
/// inserted under (`register_verified`). An instance cannot finish
/// enrollment at all unless its claimed `service_id` already has an
/// `identities` row (the enrollment binding itself carries the same
/// foreign key), so any caller that reaches `AuthorityService::authorize`
/// through a real signed request already satisfies it. What a real
/// deployment still needs, out of band -- the same way grants and schema
/// status already are -- is: an `identities` row and enrollment binding for
/// each calling service (provisioned before it enrolls), an `identities`
/// row for whatever `POLICY_EVALUATOR_ID` names, at least one grant under
/// this schema-version pair for an action to actually be allowed, and a
/// reachable evaluator process at `POLICY_EVALUATOR_AUTHORITY`. None of
/// that is a code gap; `tests/postgres_authority_repository.rs`'s ignored
/// integration tests already exercise this identity-then-schema-then-decision
/// path end to end against a real Postgres backend.
pub const NO_ARTIFACT_SCHEMA_VERSION: SchemaVersionId =
    SchemaVersionId::from_uuid(Uuid::from_u128(1));
pub const NO_ARTIFACT_PERMISSION_POLICY_SCHEMA_VERSION: SchemaVersionId =
    SchemaVersionId::from_uuid(Uuid::from_u128(2));

/// The [`SchemaVersionRefs`] every non-artifact-bearing governed action
/// should use. See [`NO_ARTIFACT_SCHEMA_VERSION`].
pub const fn no_artifact_schema_versions() -> SchemaVersionRefs {
    SchemaVersionRefs::new(
        NO_ARTIFACT_SCHEMA_VERSION,
        NO_ARTIFACT_PERMISSION_POLICY_SCHEMA_VERSION,
    )
}

/// The fact bundle for one of the two ILK-002 decision points. Request-
/// acceptance authority has no destination; route authority does. Both
/// share this one type and [`AuthorityService::authorize`] rather than two
/// separate evaluation contracts (ADR-0013).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyFacts {
    source: ActorId,
    action: ActionName,
    scope: Scope,
    schema_versions: SchemaVersionRefs,
    destination: Option<ActorId>,
}

impl PolicyFacts {
    pub const fn for_request_acceptance(
        source: ActorId,
        action: ActionName,
        scope: Scope,
        schema_versions: SchemaVersionRefs,
    ) -> Self {
        Self {
            source,
            action,
            scope,
            schema_versions,
            destination: None,
        }
    }

    pub const fn for_route(
        source: ActorId,
        action: ActionName,
        scope: Scope,
        schema_versions: SchemaVersionRefs,
        destination: ActorId,
    ) -> Self {
        Self {
            source,
            action,
            scope,
            schema_versions,
            destination: Some(destination),
        }
    }

    pub const fn source(&self) -> ActorId {
        self.source
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

    pub const fn destination(&self) -> Option<ActorId> {
        self.destination
    }

    pub const fn is_route_decision(&self) -> bool {
        self.destination.is_some()
    }
}

/// An administrator-controlled grant. `destination` distinguishes a
/// request-acceptance grant (`None`) from a route-authority grant scoped to
/// one destination (`Some`); the two decision points never share a grant.
/// `schema_versions` pins the grant to one exact artifact and
/// permission-policy schema version — a grant never applies "for any
/// version," matching ILK-002's requirement that acceptance criteria
/// reference the exact schema version in effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Grant {
    id: GrantId,
    source: ActorId,
    action: ActionName,
    scope: Scope,
    schema_versions: SchemaVersionRefs,
    destination: Option<ActorId>,
    valid_from: i64,
    valid_until: Option<i64>,
}

impl Grant {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        source: ActorId,
        action: ActionName,
        scope: Scope,
        schema_versions: SchemaVersionRefs,
        destination: Option<ActorId>,
        valid_from: i64,
        valid_until: Option<i64>,
    ) -> Result<Self, AuthorityError> {
        Self::restore(
            GrantId::new(),
            source,
            action,
            scope,
            schema_versions,
            destination,
            valid_from,
            valid_until,
        )
    }

    /// Reconstructs a grant with its already-assigned, durably stored ID.
    /// Used by repository adapters; new grants should use [`Grant::new`].
    #[allow(clippy::too_many_arguments)]
    pub fn restore(
        id: GrantId,
        source: ActorId,
        action: ActionName,
        scope: Scope,
        schema_versions: SchemaVersionRefs,
        destination: Option<ActorId>,
        valid_from: i64,
        valid_until: Option<i64>,
    ) -> Result<Self, AuthorityError> {
        if valid_from < 0 || valid_until.is_some_and(|until| until <= valid_from) {
            return Err(AuthorityError::InvalidValidityWindow);
        }
        Ok(Self {
            id,
            source,
            action,
            scope,
            schema_versions,
            destination,
            valid_from,
            valid_until,
        })
    }

    pub const fn id(&self) -> GrantId {
        self.id
    }

    pub const fn source(&self) -> ActorId {
        self.source
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

    pub const fn destination(&self) -> Option<ActorId> {
        self.destination
    }

    pub const fn valid_from(&self) -> i64 {
        self.valid_from
    }

    pub const fn valid_until(&self) -> Option<i64> {
        self.valid_until
    }

    /// Whether this grant is currently in force and matches the given facts.
    /// Request-acceptance facts (no destination) only match non-destination
    /// grants; route facts only match grants scoped to that exact
    /// destination. The grant's schema versions must match exactly, not
    /// merely be currently active — reactivating or superseding a schema
    /// version never silently extends a grant pinned to a different one.
    pub fn permits(&self, facts: &PolicyFacts, now: i64) -> bool {
        self.source == facts.source
            && self.action == facts.action
            && self.scope.matches(&facts.scope)
            && self.schema_versions == facts.schema_versions
            && self.destination == facts.destination
            && self.valid_from <= now
            && self.valid_until.is_none_or(|until| now < until)
    }
}

/// Maximum byte length of a namespaced schema name.
pub const MAX_SCHEMA_NAME_LENGTH: usize = 200;

/// Which namespace a schema version belongs to: the artifact content shape,
/// or the permission vocabulary describing actions/fields for that content.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchemaKind {
    Artifact,
    PermissionPolicy,
}

/// A namespaced, dotted schema name owned by its publishing service, such as
/// `billing.invoice`. Publishing the first version under a name claims it;
/// later versions under the same name must keep the same owner.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct SchemaName(String);

impl SchemaName {
    pub fn new(value: &str) -> Result<Self, AuthorityError> {
        if !is_valid_schema_name(value) {
            return Err(AuthorityError::InvalidSchemaName);
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for SchemaName {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

fn is_valid_schema_name(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_SCHEMA_NAME_LENGTH {
        return false;
    }

    let mut segments = value.split('.');
    let Some(namespace) = segments.next() else {
        return false;
    };
    let Some(first_segment) = segments.next() else {
        return false;
    };

    is_valid_schema_segment(namespace)
        && is_valid_schema_segment(first_segment)
        && segments.all(is_valid_schema_segment)
}

fn is_valid_schema_segment(segment: &str) -> bool {
    let mut bytes = segment.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z'))
        && bytes
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"_-".contains(&byte))
}

/// SHA-256 content digest of a published schema's declarative document. The
/// kernel treats schema content as opaque beyond this digest, exactly as it
/// treats artifact content (ILK-006).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ContentDigest([u8; 32]);

impl ContentDigest {
    pub const fn from_bytes(value: [u8; 32]) -> Self {
        Self(value)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SchemaVersionId(Uuid);

impl SchemaVersionId {
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

impl Default for SchemaVersionId {
    fn default() -> Self {
        Self::new()
    }
}

impl Display for SchemaVersionId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.0, formatter)
    }
}

impl FromStr for SchemaVersionId {
    type Err = AuthorityError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(value)
            .map(Self)
            .map_err(|_| AuthorityError::InvalidSchemaVersionId)
    }
}

/// An immutable, published schema version. Publishing MUST NOT activate a
/// schema or grant its publisher any permission — [`SchemaStatus`] is a
/// separate, administrator-controlled overlay on top of this fact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SchemaVersion {
    id: SchemaVersionId,
    kind: SchemaKind,
    name: SchemaName,
    version: i64,
    owner: ActorId,
    content_digest: ContentDigest,
    predecessor: Option<SchemaVersionId>,
    published_at: i64,
}

impl SchemaVersion {
    /// Reconstructs a schema version with its already-assigned version
    /// number, ID, and predecessor link. Used by repository adapters, which
    /// alone decide the next version number and predecessor for a name
    /// (ADR-0013's "kernel owns the facts" split applies here too: only the
    /// repository knows the current state needed to assign these).
    #[allow(clippy::too_many_arguments)]
    pub fn restore(
        id: SchemaVersionId,
        kind: SchemaKind,
        name: SchemaName,
        version: i64,
        owner: ActorId,
        content_digest: ContentDigest,
        predecessor: Option<SchemaVersionId>,
        published_at: i64,
    ) -> Result<Self, AuthorityError> {
        if version < 1 || published_at < 0 {
            return Err(AuthorityError::InvalidSchemaVersion);
        }
        Ok(Self {
            id,
            kind,
            name,
            version,
            owner,
            content_digest,
            predecessor,
            published_at,
        })
    }

    pub const fn id(&self) -> SchemaVersionId {
        self.id
    }

    pub const fn kind(&self) -> SchemaKind {
        self.kind
    }

    pub const fn name(&self) -> &SchemaName {
        &self.name
    }

    pub const fn version(&self) -> i64 {
        self.version
    }

    pub const fn owner(&self) -> ActorId {
        self.owner
    }

    pub const fn content_digest(&self) -> ContentDigest {
        self.content_digest
    }

    pub const fn predecessor(&self) -> Option<SchemaVersionId> {
        self.predecessor
    }

    pub const fn published_at(&self) -> i64 {
        self.published_at
    }
}

/// An administrator-controlled schema lifecycle state. Only an authorized
/// administrator may move a schema out of `Published`; the kernel never
/// activates, suspends, supersedes, or retires a schema on its own.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchemaStatus {
    Published,
    Active,
    Suspended,
    Superseded,
    Retired,
}

/// A schema version paired with its current administrator-controlled
/// status, as read from the repository.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SchemaRecord {
    version: SchemaVersion,
    status: SchemaStatus,
}

impl SchemaRecord {
    pub const fn restore(version: SchemaVersion, status: SchemaStatus) -> Self {
        Self { version, status }
    }

    pub const fn version(&self) -> &SchemaVersion {
        &self.version
    }

    pub const fn status(&self) -> SchemaStatus {
        self.status
    }

    pub const fn is_active(&self) -> bool {
        matches!(self.status, SchemaStatus::Active)
    }
}

/// Kernel-owned schema storage. Publication is a normal operation any
/// authenticated service may invoke for names it owns; activation,
/// suspension, supersession, and retirement are administrator-only and,
/// like grant creation, happen out-of-band rather than through this trait.
pub trait SchemaRepository: Send + Sync {
    /// Atomically assigns the next version number and predecessor link for
    /// `name` and publishes it. Returns
    /// [`AuthorityError::SchemaNamespaceConflict`] if `name` already has a
    /// published version owned by a different service.
    fn publish(
        &self,
        kind: SchemaKind,
        name: SchemaName,
        owner: ActorId,
        content_digest: ContentDigest,
        published_at: i64,
    ) -> Result<SchemaRecord, AuthorityError>;

    fn find(
        &self,
        kind: SchemaKind,
        name: &SchemaName,
        version: i64,
    ) -> Result<Option<SchemaRecord>, AuthorityError>;
}

#[derive(Clone)]
pub struct SchemaService<R> {
    repository: R,
}

impl<R> SchemaService<R>
where
    R: SchemaRepository,
{
    pub const fn new(repository: R) -> Self {
        Self { repository }
    }

    /// Publishes a new schema version. Publication alone never activates the
    /// schema or authorizes its publisher (ILK-002).
    pub fn publish(
        &self,
        kind: SchemaKind,
        name: SchemaName,
        owner: ActorId,
        content_digest: ContentDigest,
        published_at: i64,
    ) -> Result<SchemaRecord, AuthorityError> {
        if published_at < 0 {
            return Err(AuthorityError::InvalidSchemaVersion);
        }
        self.repository
            .publish(kind, name, owner, content_digest, published_at)
    }

    pub fn find(
        &self,
        kind: SchemaKind,
        name: &SchemaName,
        version: i64,
    ) -> Result<Option<SchemaRecord>, AuthorityError> {
        self.repository.find(kind, name, version)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Verdict {
    Allow,
    Deny,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct DecisionId(Uuid);

impl DecisionId {
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

impl Default for DecisionId {
    fn default() -> Self {
        Self::new()
    }
}

impl Display for DecisionId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.0, formatter)
    }
}

impl FromStr for DecisionId {
    type Err = AuthorityError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(value)
            .map(Self)
            .map_err(|_| AuthorityError::InvalidDecisionId)
    }
}

/// A pinned ILK-002 decision. Once recorded it is never re-evaluated: a
/// later policy or grant change produces a new decision for a new request or
/// route, never a silent change to this one (ILK-004).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityDecision {
    id: DecisionId,
    facts: PolicyFacts,
    verdict: Verdict,
    evaluator: ActorId,
    policy_bundle_version: Option<PolicyBundleVersion>,
    decided_at: i64,
}

impl AuthorityDecision {
    /// Reconstructs a decision with its already-assigned, durably recorded
    /// ID. Used by decision-record repository adapters.
    pub const fn restore(
        id: DecisionId,
        facts: PolicyFacts,
        verdict: Verdict,
        evaluator: ActorId,
        policy_bundle_version: Option<PolicyBundleVersion>,
        decided_at: i64,
    ) -> Self {
        Self {
            id,
            facts,
            verdict,
            evaluator,
            policy_bundle_version,
            decided_at,
        }
    }

    pub const fn is_allowed(&self) -> bool {
        matches!(self.verdict, Verdict::Allow)
    }

    pub const fn id(&self) -> DecisionId {
        self.id
    }

    pub const fn facts(&self) -> &PolicyFacts {
        &self.facts
    }

    pub const fn verdict(&self) -> Verdict {
        self.verdict
    }

    pub const fn evaluator(&self) -> ActorId {
        self.evaluator
    }

    pub const fn policy_bundle_version(&self) -> Option<&PolicyBundleVersion> {
        self.policy_bundle_version.as_ref()
    }

    pub const fn decided_at(&self) -> i64 {
        self.decided_at
    }
}

/// What an evaluator returns for facts it was actually able to evaluate.
/// Absence of this — an `Err` from [`PolicyEvaluator::evaluate`] — is always
/// treated as denial by [`AuthorityService`] (ADR-0013); this type has no
/// variant for "no answer" because that case never reaches it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyEvaluation {
    verdict: Verdict,
    policy_bundle_version: PolicyBundleVersion,
}

impl PolicyEvaluation {
    pub const fn new(verdict: Verdict, policy_bundle_version: PolicyBundleVersion) -> Self {
        Self {
            verdict,
            policy_bundle_version,
        }
    }
}

/// Owns only the allow/deny algorithm. Implementations MUST NOT store
/// authorization data of their own — every fact and grant they see comes
/// from the kernel's call (ADR-0013).
pub trait PolicyEvaluator: Send + Sync {
    fn evaluate(
        &self,
        facts: &PolicyFacts,
        grants: &[Grant],
    ) -> Result<PolicyEvaluation, AuthorityError>;
}

/// Kernel-owned grant storage. Read-only from [`AuthorityService`]'s
/// perspective; grant and schema administration (creation, activation,
/// revocation) is a separate, not-yet-built administrative surface.
pub trait AuthorityRepository: Send + Sync {
    fn matching_grants(&self, facts: &PolicyFacts, now: i64) -> Result<Vec<Grant>, AuthorityError>;
}

/// Durably records a pinned decision. This is kernel bookkeeping, not
/// administration: there is no out-of-band function here, because nothing
/// but the kernel itself ever produces a decision to record.
pub trait AuthorityDecisionRecorder: Send + Sync {
    fn record(&self, decision: &AuthorityDecision) -> Result<(), AuthorityError>;
}

#[derive(Clone)]
pub struct AuthorityService<R, E, D> {
    repository: R,
    evaluator: E,
    evaluator_id: ActorId,
    decisions: D,
}

impl<R, E, D> AuthorityService<R, E, D>
where
    R: AuthorityRepository,
    E: PolicyEvaluator,
    D: AuthorityDecisionRecorder,
{
    pub const fn new(repository: R, evaluator: E, evaluator_id: ActorId, decisions: D) -> Self {
        Self {
            repository,
            evaluator,
            evaluator_id,
            decisions,
        }
    }

    /// Assembles the currently matching grants, asks the evaluator for a
    /// verdict, and durably records the pinned result before returning it.
    /// An unreachable, erroring, or malformed evaluator response is recorded
    /// as denial with no policy bundle version, never as an implicit allow
    /// (ADR-0013). If the decision cannot be durably recorded, `authorize`
    /// fails rather than returning an unrecorded decision — the same
    /// fail-closed posture the kernel already takes toward every other
    /// durability dependency.
    pub fn authorize(
        &self,
        facts: PolicyFacts,
        now: i64,
    ) -> Result<AuthorityDecision, AuthorityError> {
        let grants = self.repository.matching_grants(&facts, now)?;
        let (verdict, policy_bundle_version) = match self.evaluator.evaluate(&facts, &grants) {
            Ok(evaluation) => (evaluation.verdict, Some(evaluation.policy_bundle_version)),
            Err(_) => (Verdict::Deny, None),
        };
        let decision = AuthorityDecision::restore(
            DecisionId::new(),
            facts,
            verdict,
            self.evaluator_id,
            policy_bundle_version,
            now,
        );
        self.decisions.record(&decision)?;
        Ok(decision)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthorityError {
    InvalidScope,
    InvalidPolicyBundleVersion,
    InvalidValidityWindow,
    InvalidGrantId,
    InvalidSchemaName,
    InvalidSchemaVersionId,
    InvalidSchemaVersion,
    InvalidDecisionId,
    SchemaNamespaceConflict(SchemaName),
    Repository(String),
    Evaluator(String),
}

impl Display for AuthorityError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidScope => {
                formatter.write_str("scope must be non-empty, bounded, and untrimmed-safe")
            }
            Self::InvalidPolicyBundleVersion => formatter
                .write_str("policy bundle version must be non-empty and within the length limit"),
            Self::InvalidValidityWindow => formatter.write_str("grant validity window is invalid"),
            Self::InvalidGrantId => formatter.write_str("grant ID must be a UUID"),
            Self::InvalidSchemaName => formatter.write_str(
                "schema name must be a dotted, namespaced, lower-case identifier within the length limit",
            ),
            Self::InvalidSchemaVersionId => formatter.write_str("schema version ID must be a UUID"),
            Self::InvalidSchemaVersion => {
                formatter.write_str("schema version number or publication time is invalid")
            }
            Self::InvalidDecisionId => formatter.write_str("decision ID must be a UUID"),
            Self::SchemaNamespaceConflict(name) => {
                write!(formatter, "schema name {name} is owned by a different service")
            }
            Self::Repository(message) => {
                write!(formatter, "authority repository failed: {message}")
            }
            Self::Evaluator(message) => write!(formatter, "policy evaluator failed: {message}"),
        }
    }
}

impl Error for AuthorityError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn traces_to_authority_requirement() {
        assert_eq!(REQUIREMENT.id, "ILK-002");
        assert_eq!(REQUIREMENT.capability, "Authority");
    }

    #[test]
    fn no_artifact_schema_versions_are_stable_and_distinct() {
        let first = no_artifact_schema_versions();
        let second = no_artifact_schema_versions();

        assert_eq!(first, second);
        assert_ne!(first.artifact(), first.permission_policy());
    }

    #[test]
    fn a_grant_under_the_no_artifact_schema_versions_permits_matching_facts() {
        let source = ActorId::new();
        let action = ActionName::new("subscription.create").unwrap();
        let grant = Grant::new(
            source,
            action.clone(),
            Scope::wildcard(),
            no_artifact_schema_versions(),
            None,
            0,
            None,
        )
        .unwrap();
        let facts = PolicyFacts::for_request_acceptance(
            source,
            action,
            Scope::wildcard(),
            no_artifact_schema_versions(),
        );

        assert!(grant.permits(&facts, 1));
    }
}
