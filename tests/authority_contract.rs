//! Goal: independently verify the public minimum ILK-002 Authority contract.

use std::sync::{Arc, Mutex};

use infernal_law::kernel::authority::{
    AuthorityDecision, AuthorityDecisionRecorder, AuthorityError, AuthorityRepository,
    AuthorityService, ContentDigest, Grant, PolicyBundleVersion, PolicyEvaluation, PolicyEvaluator,
    PolicyFacts, SchemaKind, SchemaName, SchemaRecord, SchemaRepository, SchemaService,
    SchemaStatus, SchemaVersion, SchemaVersionId, Scope, Verdict,
};
use infernal_law::kernel::identity::ActorId;
use infernal_law::kernel::requests::ActionName;

#[derive(Clone, Default)]
struct MemoryGrants(Arc<Mutex<Vec<Grant>>>);

impl MemoryGrants {
    fn insert(&self, grant: Grant) {
        self.0.lock().unwrap().push(grant);
    }
}

impl AuthorityRepository for MemoryGrants {
    fn matching_grants(&self, facts: &PolicyFacts, now: i64) -> Result<Vec<Grant>, AuthorityError> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .iter()
            .filter(|grant| grant.permits(facts, now))
            .cloned()
            .collect())
    }
}

#[derive(Clone, Default)]
struct MemorySchemas(Arc<Mutex<Vec<SchemaRecord>>>);

impl SchemaRepository for MemorySchemas {
    fn publish(
        &self,
        kind: SchemaKind,
        name: SchemaName,
        owner: ActorId,
        content_digest: ContentDigest,
        published_at: i64,
    ) -> Result<SchemaRecord, AuthorityError> {
        let mut records = self.0.lock().unwrap();
        let latest = records
            .iter()
            .filter(|record| record.version().kind() == kind && record.version().name() == &name)
            .max_by_key(|record| record.version().version());
        if let Some(latest) = latest {
            if latest.version().owner() != owner {
                return Err(AuthorityError::SchemaNamespaceConflict(name));
            }
        }
        let next_version = latest.map_or(1, |record| record.version().version() + 1);
        let predecessor = latest.map(|record| record.version().id());
        let version = SchemaVersion::restore(
            SchemaVersionId::new(),
            kind,
            name,
            next_version,
            owner,
            content_digest,
            predecessor,
            published_at,
        )?;
        let record = SchemaRecord::restore(version, SchemaStatus::Published);
        records.push(record.clone());
        Ok(record)
    }

    fn find(
        &self,
        kind: SchemaKind,
        name: &SchemaName,
        version: i64,
    ) -> Result<Option<SchemaRecord>, AuthorityError> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .iter()
            .find(|record| {
                record.version().kind() == kind
                    && record.version().name() == name
                    && record.version().version() == version
            })
            .cloned())
    }
}

#[derive(Clone, Default)]
struct MemoryDecisions(Arc<Mutex<Vec<AuthorityDecision>>>);

impl AuthorityDecisionRecorder for MemoryDecisions {
    fn record(&self, decision: &AuthorityDecision) -> Result<(), AuthorityError> {
        self.0.lock().unwrap().push(decision.clone());
        Ok(())
    }
}

/// Allows only when at least one grant was handed to it: the simplest
/// possible "a grant exists" policy algorithm.
struct AllowIfAnyGrant;

impl PolicyEvaluator for AllowIfAnyGrant {
    fn evaluate(
        &self,
        _facts: &PolicyFacts,
        grants: &[Grant],
    ) -> Result<PolicyEvaluation, AuthorityError> {
        let verdict = if grants.is_empty() {
            Verdict::Deny
        } else {
            Verdict::Allow
        };
        Ok(PolicyEvaluation::new(verdict, bundle_version("v1")))
    }
}

struct UnreachableEvaluator;

impl PolicyEvaluator for UnreachableEvaluator {
    fn evaluate(
        &self,
        _facts: &PolicyFacts,
        _grants: &[Grant],
    ) -> Result<PolicyEvaluation, AuthorityError> {
        Err(AuthorityError::Evaluator("connection refused".to_owned()))
    }
}

fn bundle_version(value: &str) -> PolicyBundleVersion {
    PolicyBundleVersion::new(value).unwrap()
}

fn action(value: &str) -> ActionName {
    ActionName::new(value).unwrap()
}

fn scope(value: &str) -> Scope {
    Scope::new(value).unwrap()
}

fn schema_name(value: &str) -> SchemaName {
    SchemaName::new(value).unwrap()
}

fn digest(byte: u8) -> ContentDigest {
    ContentDigest::from_bytes([byte; 32])
}

#[test]
fn default_deny_when_no_grant_matches() {
    let service = AuthorityService::new(
        MemoryGrants::default(),
        AllowIfAnyGrant,
        ActorId::new(),
        MemoryDecisions::default(),
    );
    let facts = PolicyFacts::for_request_acceptance(
        ActorId::new(),
        action("billing.invoice.submit"),
        scope("*"),
    );

    let decision = service.authorize(facts, 1_000).unwrap();

    assert!(!decision.is_allowed());
    assert_eq!(decision.verdict(), Verdict::Deny);
}

#[test]
fn matching_grant_allows_and_pins_the_evaluated_policy_bundle_version() {
    let repository = MemoryGrants::default();
    let source = ActorId::new();
    let evaluator_id = ActorId::new();
    repository.insert(
        Grant::new(
            source,
            action("billing.invoice.submit"),
            Scope::wildcard(),
            None,
            0,
            None,
        )
        .unwrap(),
    );
    let service = AuthorityService::new(
        repository,
        AllowIfAnyGrant,
        evaluator_id,
        MemoryDecisions::default(),
    );
    let facts = PolicyFacts::for_request_acceptance(
        source,
        action("billing.invoice.submit"),
        scope("invoice-42"),
    );

    let decision = service.authorize(facts, 1_000).unwrap();

    assert!(decision.is_allowed());
    assert_eq!(decision.evaluator(), evaluator_id);
    assert_eq!(
        decision
            .policy_bundle_version()
            .map(PolicyBundleVersion::as_str),
        Some("v1")
    );
}

#[test]
fn unreachable_evaluator_is_denied_never_implicitly_allowed() {
    let repository = MemoryGrants::default();
    let source = ActorId::new();
    repository.insert(
        Grant::new(
            source,
            action("billing.invoice.submit"),
            Scope::wildcard(),
            None,
            0,
            None,
        )
        .unwrap(),
    );
    let service = AuthorityService::new(
        repository,
        UnreachableEvaluator,
        ActorId::new(),
        MemoryDecisions::default(),
    );
    let facts = PolicyFacts::for_request_acceptance(
        source,
        action("billing.invoice.submit"),
        scope("invoice-42"),
    );

    let decision = service.authorize(facts, 1_000).unwrap();

    assert!(!decision.is_allowed());
    assert_eq!(decision.policy_bundle_version(), None);
}

#[test]
fn expired_grant_does_not_permit() {
    let repository = MemoryGrants::default();
    let source = ActorId::new();
    repository.insert(
        Grant::new(
            source,
            action("billing.invoice.submit"),
            Scope::wildcard(),
            None,
            0,
            Some(500),
        )
        .unwrap(),
    );
    let service = AuthorityService::new(
        repository,
        AllowIfAnyGrant,
        ActorId::new(),
        MemoryDecisions::default(),
    );
    let facts = PolicyFacts::for_request_acceptance(
        source,
        action("billing.invoice.submit"),
        scope("invoice-42"),
    );

    let decision = service.authorize(facts, 1_000).unwrap();

    assert!(!decision.is_allowed());
}

#[test]
fn request_acceptance_and_route_decisions_do_not_share_grants() {
    let repository = MemoryGrants::default();
    let source = ActorId::new();
    let destination = ActorId::new();
    repository.insert(
        Grant::new(
            source,
            action("work.item.submit"),
            Scope::wildcard(),
            Some(destination),
            0,
            None,
        )
        .unwrap(),
    );
    let service = AuthorityService::new(
        repository,
        AllowIfAnyGrant,
        ActorId::new(),
        MemoryDecisions::default(),
    );

    let acceptance_facts =
        PolicyFacts::for_request_acceptance(source, action("work.item.submit"), scope("*"));
    let acceptance_decision = service.authorize(acceptance_facts, 1_000).unwrap();
    assert!(
        !acceptance_decision.is_allowed(),
        "a route-scoped grant must not authorize request acceptance"
    );

    let route_facts =
        PolicyFacts::for_route(source, action("work.item.submit"), scope("*"), destination);
    let route_decision = service.authorize(route_facts, 1_000).unwrap();
    assert!(route_decision.is_allowed());
}

#[test]
fn wildcard_scope_grant_matches_any_requested_scope() {
    let repository = MemoryGrants::default();
    let source = ActorId::new();
    repository.insert(
        Grant::new(
            source,
            action("billing.invoice.submit"),
            Scope::wildcard(),
            None,
            0,
            None,
        )
        .unwrap(),
    );
    let service = AuthorityService::new(
        repository,
        AllowIfAnyGrant,
        ActorId::new(),
        MemoryDecisions::default(),
    );
    let facts = PolicyFacts::for_request_acceptance(
        source,
        action("billing.invoice.submit"),
        scope("any-invoice-id"),
    );

    let decision = service.authorize(facts, 1_000).unwrap();

    assert!(decision.is_allowed());
}

#[test]
fn malformed_scope_and_policy_bundle_version_are_rejected() {
    assert_eq!(Scope::new(""), Err(AuthorityError::InvalidScope));
    assert_eq!(Scope::new(" padded "), Err(AuthorityError::InvalidScope));
    assert_eq!(
        PolicyBundleVersion::new(""),
        Err(AuthorityError::InvalidPolicyBundleVersion)
    );
}

#[test]
fn invalid_grant_validity_window_is_rejected() {
    let source = ActorId::new();
    assert_eq!(
        Grant::new(
            source,
            action("billing.invoice.submit"),
            Scope::wildcard(),
            None,
            100,
            Some(100),
        ),
        Err(AuthorityError::InvalidValidityWindow)
    );
    assert_eq!(
        Grant::new(
            source,
            action("billing.invoice.submit"),
            Scope::wildcard(),
            None,
            -1,
            None,
        ),
        Err(AuthorityError::InvalidValidityWindow)
    );
}

#[test]
fn publishing_a_schema_never_activates_it() {
    let schemas = SchemaService::new(MemorySchemas::default());
    let owner = ActorId::new();

    let record = schemas
        .publish(
            SchemaKind::Artifact,
            schema_name("billing.invoice"),
            owner,
            digest(1),
            1_000,
        )
        .unwrap();

    assert_eq!(record.version().version(), 1);
    assert_eq!(record.version().predecessor(), None);
    assert_eq!(record.status(), SchemaStatus::Published);
    assert!(
        !record.is_active(),
        "publication alone must not activate a schema"
    );
}

#[test]
fn later_versions_chain_to_their_predecessor_and_increment() {
    let schemas = SchemaService::new(MemorySchemas::default());
    let owner = ActorId::new();
    let name = schema_name("billing.invoice");

    let first = schemas
        .publish(SchemaKind::Artifact, name.clone(), owner, digest(1), 1_000)
        .unwrap();
    let second = schemas
        .publish(SchemaKind::Artifact, name, owner, digest(2), 2_000)
        .unwrap();

    assert_eq!(second.version().version(), 2);
    assert_eq!(second.version().predecessor(), Some(first.version().id()));
}

#[test]
fn a_different_service_cannot_publish_under_an_owned_schema_name() {
    let schemas = SchemaService::new(MemorySchemas::default());
    let name = schema_name("billing.invoice");
    schemas
        .publish(
            SchemaKind::Artifact,
            name.clone(),
            ActorId::new(),
            digest(1),
            1_000,
        )
        .unwrap();

    let result = schemas.publish(SchemaKind::Artifact, name, ActorId::new(), digest(2), 2_000);

    assert!(matches!(
        result,
        Err(AuthorityError::SchemaNamespaceConflict(_))
    ));
}

#[test]
fn artifact_and_permission_policy_schemas_are_independent_namespaces() {
    let schemas = SchemaService::new(MemorySchemas::default());
    let name = schema_name("billing.invoice");
    let artifact_owner = ActorId::new();
    let policy_owner = ActorId::new();

    let artifact = schemas
        .publish(
            SchemaKind::Artifact,
            name.clone(),
            artifact_owner,
            digest(1),
            1_000,
        )
        .unwrap();
    let policy = schemas
        .publish(
            SchemaKind::PermissionPolicy,
            name,
            policy_owner,
            digest(2),
            1_000,
        )
        .unwrap();

    assert_eq!(artifact.version().version(), 1);
    assert_eq!(policy.version().version(), 1);
    assert_ne!(artifact.version().owner(), policy.version().owner());
}

#[test]
fn find_returns_none_for_an_unpublished_version() {
    let schemas = SchemaService::new(MemorySchemas::default());
    let name = schema_name("billing.invoice");
    schemas
        .publish(
            SchemaKind::Artifact,
            name.clone(),
            ActorId::new(),
            digest(1),
            1_000,
        )
        .unwrap();

    assert_eq!(schemas.find(SchemaKind::Artifact, &name, 2).unwrap(), None);
}

#[test]
fn malformed_schema_names_are_rejected() {
    assert_eq!(SchemaName::new(""), Err(AuthorityError::InvalidSchemaName));
    assert_eq!(
        SchemaName::new("invoice"),
        Err(AuthorityError::InvalidSchemaName)
    );
    assert_eq!(
        SchemaName::new("Billing.Invoice"),
        Err(AuthorityError::InvalidSchemaName)
    );
}

#[test]
fn invalid_schema_version_facts_are_rejected() {
    let owner = ActorId::new();
    assert_eq!(
        SchemaVersion::restore(
            SchemaVersionId::new(),
            SchemaKind::Artifact,
            schema_name("billing.invoice"),
            0,
            owner,
            digest(1),
            None,
            1_000,
        ),
        Err(AuthorityError::InvalidSchemaVersion)
    );
    assert_eq!(
        SchemaVersion::restore(
            SchemaVersionId::new(),
            SchemaKind::Artifact,
            schema_name("billing.invoice"),
            1,
            owner,
            digest(1),
            None,
            -1,
        ),
        Err(AuthorityError::InvalidSchemaVersion)
    );
}

#[test]
fn every_authorize_call_durably_records_exactly_one_decision() {
    let decisions = MemoryDecisions::default();
    let service = AuthorityService::new(
        MemoryGrants::default(),
        AllowIfAnyGrant,
        ActorId::new(),
        decisions.clone(),
    );
    let facts = PolicyFacts::for_request_acceptance(
        ActorId::new(),
        action("billing.invoice.submit"),
        scope("*"),
    );

    let returned = service.authorize(facts, 1_000).unwrap();

    let recorded = decisions.0.lock().unwrap();
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].id(), returned.id());
    assert_eq!(recorded[0], returned);
}

struct FailingDecisionRecorder;

impl AuthorityDecisionRecorder for FailingDecisionRecorder {
    fn record(&self, _decision: &AuthorityDecision) -> Result<(), AuthorityError> {
        Err(AuthorityError::Repository(
            "decision store unavailable".to_owned(),
        ))
    }
}

#[test]
fn authorize_fails_rather_than_return_an_unrecorded_decision() {
    let service = AuthorityService::new(
        MemoryGrants::default(),
        AllowIfAnyGrant,
        ActorId::new(),
        FailingDecisionRecorder,
    );
    let facts = PolicyFacts::for_request_acceptance(
        ActorId::new(),
        action("billing.invoice.submit"),
        scope("*"),
    );

    assert!(service.authorize(facts, 1_000).is_err());
}
