//! Goal: implement ILK-002's `PolicyEvaluator` as a real, signed outbound
//! HTTP call to an external policy evaluator (ADR-0013), signing with the
//! kernel's own long-lived instance credential -- the same key published at
//! `GET /v1/kernel-identity` (ADR-0014) -- rather than a second key nothing
//! would recognize.

use std::time::{SystemTime, UNIX_EPOCH};

use infernal_client::{Client, ClientPublicKey, RequestParts, SignedRequest};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::kernel::authority::{
    AuthorityError, Grant, PolicyBundleVersion, PolicyEvaluation, PolicyEvaluator, PolicyFacts,
    Verdict,
};
use crate::kernel::instance_keys::{InstanceCredential, InstancePublicKey};

const EVALUATE_PATH: &str = "/v1/authority/evaluate";
const SIGNATURE_VALIDITY_SECONDS: i64 = 30;

pub struct HttpPolicyEvaluator<'a> {
    client: Client,
    credential: &'a InstanceCredential,
    authority: String,
}

impl<'a> HttpPolicyEvaluator<'a> {
    /// `authority` is the evaluator's host (and, if needed, port), for
    /// example `policy-evaluator.example.test` -- the same shape as an HTTP
    /// `Host` header, never including a scheme or path.
    pub fn new(
        credential: &'a InstanceCredential,
        authority: impl Into<String>,
    ) -> Result<Self, AuthorityError> {
        let client = Client::new().map_err(|error| AuthorityError::Evaluator(error.to_string()))?;
        Ok(Self {
            client,
            credential,
            authority: authority.into(),
        })
    }

    /// Like [`HttpPolicyEvaluator::new`], but additionally trusts
    /// `extra_root_certificate_pem` -- for an evaluator reachable only
    /// behind a private or self-signed certificate authority, which this
    /// crate's default public root store would otherwise reject. Mirrors
    /// `KernelClient::with_extra_root_certificate` in the reference
    /// services on the other side of this same call.
    pub fn with_extra_root_certificate(
        credential: &'a InstanceCredential,
        authority: impl Into<String>,
        extra_root_certificate_pem: &[u8],
    ) -> Result<Self, AuthorityError> {
        let client = Client::with_extra_root_certificate(extra_root_certificate_pem)
            .map_err(|error| AuthorityError::Evaluator(error.to_string()))?;
        Ok(Self {
            client,
            credential,
            authority: authority.into(),
        })
    }
}

impl PolicyEvaluator for HttpPolicyEvaluator<'_> {
    fn evaluate(
        &self,
        facts: &PolicyFacts,
        grants: &[Grant],
    ) -> Result<PolicyEvaluation, AuthorityError> {
        let signed = build_signed_request(self.credential, &self.authority, facts, grants)?;
        let response = self
            .client
            .send(&signed)
            .map_err(|error| AuthorityError::Evaluator(error.to_string()))?;
        parse_response(response.status, &response.body)
    }
}

/// Builds the signed `POST /v1/authority/evaluate` request, without sending
/// it. Split out from [`HttpPolicyEvaluator::evaluate`] so the signing
/// logic can be verified directly against the kernel's own
/// `ServiceRequestVerifier` without needing a real (HTTPS-only) socket.
fn build_signed_request(
    credential: &InstanceCredential,
    authority: &str,
    facts: &PolicyFacts,
    grants: &[Grant],
) -> Result<SignedRequest, AuthorityError> {
    let body = serde_json::to_vec(&EvaluateRequest::from_facts_and_grants(facts, grants))
        .map_err(|error| AuthorityError::Evaluator(error.to_string()))?;
    let request_id = Uuid::new_v4();
    let nonce = infernal_client::generate_nonce()
        .map_err(|error| AuthorityError::Evaluator(error.to_string()))?;
    let now = unix_time();
    let parts = RequestParts::new(
        "POST",
        authority,
        EVALUATE_PATH,
        "application/json",
        &body,
        request_id,
    )
    .map_err(|error| AuthorityError::Evaluator(error.to_string()))?;
    let public_key = client_public_key(credential.public_key())?;
    SignedRequest::sign_with(
        parts,
        &public_key,
        now,
        now + SIGNATURE_VALIDITY_SECONDS,
        &nonce,
        |message| *credential.sign(message).as_bytes(),
    )
    .map_err(|error| AuthorityError::Evaluator(error.to_string()))
}

/// Interprets an HTTP status and body from the evaluator, without any
/// network dependency, so this logic is independently testable with
/// synthetic responses.
fn parse_response(status: u16, body: &[u8]) -> Result<PolicyEvaluation, AuthorityError> {
    if !(200..300).contains(&status) {
        return Err(AuthorityError::Evaluator(format!(
            "policy evaluator returned status {status}"
        )));
    }
    let parsed: EvaluateResponse = serde_json::from_slice(body)
        .map_err(|error| AuthorityError::Evaluator(error.to_string()))?;
    parsed.into_evaluation()
}

fn client_public_key(public_key: &InstancePublicKey) -> Result<ClientPublicKey, AuthorityError> {
    ClientPublicKey::restore(
        *public_key.service_id().as_uuid(),
        *public_key.instance_id().as_uuid(),
        *public_key.key_id().as_uuid(),
        *public_key.public_key_bytes(),
    )
    .map_err(|error| AuthorityError::Evaluator(error.to_string()))
}

fn unix_time() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    )
    .unwrap_or(i64::MAX)
}

#[derive(Serialize)]
struct EvaluateGrant {
    grant_id: String,
    source_service_id: String,
    action: String,
    scope: String,
    artifact_schema_version_id: String,
    permission_policy_schema_version_id: String,
    destination_service_id: Option<String>,
    valid_from: i64,
    valid_until: Option<i64>,
}

impl From<&Grant> for EvaluateGrant {
    fn from(grant: &Grant) -> Self {
        Self {
            grant_id: grant.id().to_string(),
            source_service_id: grant.source().to_string(),
            action: grant.action().as_str().to_owned(),
            scope: grant.scope().as_str().to_owned(),
            artifact_schema_version_id: grant.schema_versions().artifact().to_string(),
            permission_policy_schema_version_id: grant
                .schema_versions()
                .permission_policy()
                .to_string(),
            destination_service_id: grant.destination().map(|id| id.to_string()),
            valid_from: grant.valid_from(),
            valid_until: grant.valid_until(),
        }
    }
}

#[derive(Serialize)]
struct EvaluateRequest {
    source_service_id: String,
    action: String,
    scope: String,
    artifact_schema_version_id: String,
    permission_policy_schema_version_id: String,
    destination_service_id: Option<String>,
    grants: Vec<EvaluateGrant>,
}

impl EvaluateRequest {
    fn from_facts_and_grants(facts: &PolicyFacts, grants: &[Grant]) -> Self {
        Self {
            source_service_id: facts.source().to_string(),
            action: facts.action().as_str().to_owned(),
            scope: facts.scope().as_str().to_owned(),
            artifact_schema_version_id: facts.schema_versions().artifact().to_string(),
            permission_policy_schema_version_id: facts
                .schema_versions()
                .permission_policy()
                .to_string(),
            destination_service_id: facts.destination().map(|id| id.to_string()),
            grants: grants.iter().map(EvaluateGrant::from).collect(),
        }
    }
}

#[derive(Deserialize)]
struct EvaluateResponse {
    verdict: String,
    policy_bundle_version: String,
}

impl EvaluateResponse {
    fn into_evaluation(self) -> Result<PolicyEvaluation, AuthorityError> {
        let verdict = match self.verdict.as_str() {
            "allow" => Verdict::Allow,
            "deny" => Verdict::Deny,
            other => {
                return Err(AuthorityError::Evaluator(format!(
                    "unknown verdict: {other}"
                )));
            }
        };
        let policy_bundle_version = PolicyBundleVersion::new(&self.policy_bundle_version)
            .map_err(|_| AuthorityError::Evaluator("invalid policy bundle version".to_owned()))?;
        Ok(PolicyEvaluation::new(verdict, policy_bundle_version))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::authority::{SchemaVersionId, SchemaVersionRefs, Scope};
    use crate::kernel::identity::ActorId;
    use crate::kernel::instance_keys::InstanceId;
    use crate::kernel::instance_registry::{InstanceRegistryError, RegisteredInstance};
    use crate::kernel::requests::ActionName;
    use crate::kernel::service_requests::{
        EligibleInstanceResolver, ServiceRequestParts, ServiceRequestVerifier, SignedServiceRequest,
    };

    #[derive(Clone)]
    struct KnownInstance(RegisteredInstance);

    impl EligibleInstanceResolver for KnownInstance {
        fn find_eligible(
            &self,
            instance_id: InstanceId,
            now: i64,
        ) -> Result<RegisteredInstance, InstanceRegistryError> {
            if self.0.public_key().instance_id() != instance_id {
                return Err(InstanceRegistryError::NotFound(instance_id));
            }
            if !self.0.is_eligible_at(now) {
                return Err(InstanceRegistryError::Expired(instance_id));
            }
            Ok(self.0.clone())
        }
    }

    fn facts_and_grant() -> (PolicyFacts, Grant) {
        let source = ActorId::new();
        let action = ActionName::new("billing.invoice.submit").unwrap();
        let scope = Scope::new("invoice-42").unwrap();
        let schema_versions =
            SchemaVersionRefs::new(SchemaVersionId::new(), SchemaVersionId::new());
        let facts = PolicyFacts::for_request_acceptance(
            source,
            action.clone(),
            scope.clone(),
            schema_versions,
        );
        let grant = Grant::new(source, action, scope, schema_versions, None, 0, None).unwrap();
        (facts, grant)
    }

    #[test]
    fn build_signed_request_verifies_under_the_kernels_own_verifier() {
        let credential = InstanceCredential::generate(ActorId::new());
        let registered = RegisteredInstance::create(
            credential.public_key().clone(),
            "https://evaluator.example.test",
            0,
            i64::MAX,
        )
        .unwrap();
        let verifier = ServiceRequestVerifier::new(KnownInstance(registered));
        let (facts, grant) = facts_and_grant();

        let signed = build_signed_request(
            &credential,
            "policy-evaluator.example.test",
            &facts,
            std::slice::from_ref(&grant),
        )
        .unwrap();

        let kernel_parts = ServiceRequestParts::new(
            "POST",
            "policy-evaluator.example.test",
            EVALUATE_PATH,
            "application/json",
            &serde_json::to_vec(&EvaluateRequest::from_facts_and_grants(
                &facts,
                std::slice::from_ref(&grant),
            ))
            .unwrap(),
            signed.parts().request_id(),
        )
        .unwrap();
        let kernel_request = SignedServiceRequest::from_wire(
            kernel_parts,
            &signed.service_id().to_string(),
            &signed.instance_id().to_string(),
            signed.content_digest(),
            signed.signature_input(),
            signed.signature(),
        )
        .unwrap();

        let now = unix_time();
        let verified = verifier.verify(&kernel_request, now).unwrap();
        assert_eq!(
            verified.service_id(),
            ActorId::from_uuid(*credential.public_key().service_id().as_uuid())
        );
    }

    #[test]
    fn parse_response_accepts_a_well_formed_allow_verdict() {
        let evaluation =
            parse_response(200, br#"{"verdict":"allow","policy_bundle_version":"v1"}"#).unwrap();

        assert_eq!(
            evaluation,
            PolicyEvaluation::new(Verdict::Allow, PolicyBundleVersion::new("v1").unwrap())
        );
    }

    #[test]
    fn parse_response_rejects_a_non_success_status() {
        assert!(matches!(
            parse_response(503, br#"{"verdict":"deny","policy_bundle_version":"v1"}"#),
            Err(AuthorityError::Evaluator(_))
        ));
    }

    #[test]
    fn parse_response_rejects_an_unknown_verdict() {
        assert!(matches!(
            parse_response(200, br#"{"verdict":"maybe","policy_bundle_version":"v1"}"#),
            Err(AuthorityError::Evaluator(_))
        ));
    }

    #[test]
    fn parse_response_rejects_malformed_json() {
        assert!(matches!(
            parse_response(200, b"not json"),
            Err(AuthorityError::Evaluator(_))
        ));
    }
}
