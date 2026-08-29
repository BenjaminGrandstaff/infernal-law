//! Goal: independently verify the public minimum ILK-002 Authority contract.

use std::sync::{Arc, Mutex};

use infernal_law::kernel::authority::{
    AuthorityError, AuthorityRepository, AuthorityService, Grant, PolicyBundleVersion,
    PolicyEvaluation, PolicyEvaluator, PolicyFacts, Scope, Verdict,
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

#[test]
fn default_deny_when_no_grant_matches() {
    let service = AuthorityService::new(MemoryGrants::default(), AllowIfAnyGrant, ActorId::new());
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
    let service = AuthorityService::new(repository, AllowIfAnyGrant, evaluator_id);
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
    let service = AuthorityService::new(repository, UnreachableEvaluator, ActorId::new());
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
    let service = AuthorityService::new(repository, AllowIfAnyGrant, ActorId::new());
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
    let service = AuthorityService::new(repository, AllowIfAnyGrant, ActorId::new());

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
    let service = AuthorityService::new(repository, AllowIfAnyGrant, ActorId::new());
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
