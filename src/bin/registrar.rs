//! Goal: reconcile the administrative state that ADR-0008 enrollment
//! depends on -- identities, enrollment bindings, communication admission,
//! and authority grants -- from a declarative manifest, without ever
//! exposing a SQL command surface through the kernel (ADR-0007).
//!
//! This is the registrar of ADR-0015. It is a separate process with its own
//! PostgreSQL credential, deliberately not reachable through infernal-law's
//! HTTP API: the kernel remains the sole mediation boundary for callers,
//! while administrative change happens out of band and is auditable.
//!
//! It is idempotent by construction. Running it twice changes nothing the
//! second time, so it is safe as a Job that runs on every deploy.
//!
//! ServiceAccount UIDs are resolved from the Kubernetes API rather than
//! taken from the manifest. `service_enrollment_bindings` pins a binding to
//! one specific ServiceAccount object; deleting and recreating that
//! ServiceAccount changes its UID and silently breaks enrollment while every
//! manifest still looks correct. Reconciling the UID turns that outage into
//! a no-op.

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::process::ExitCode;
use std::time::Duration;

use r2d2_postgres::postgres::{Client as PostgresClient, NoTls};
use reqwest::blocking::Client as HttpClient;
use serde::Deserialize;

const DATABASE_URL_ENV: &str = "DATABASE_URL";
const MANIFEST_PATH_ENV: &str = "REGISTRAR_MANIFEST";
const ADMINISTRATOR_ENV: &str = "REGISTRAR_ADMINISTRATOR";
const API_URL_ENV: &str = "KUBERNETES_API_URL";
const TOKEN_PATH_ENV: &str = "REGISTRAR_TOKEN_PATH";
const CA_PATH_ENV: &str = "KUBERNETES_CA_PATH";
/// Opt-in. Reconciliation is additive by default: removing a service from
/// the manifest does nothing unless this is set. Withdrawing authority is
/// the one direction where a mistake in the manifest -- or running an old
/// copy of it -- causes an outage rather than an over-permission, so it is
/// never the default.
const PRUNE_ENV: &str = "REGISTRAR_PRUNE";

const DEFAULT_API_URL: &str = "https://kubernetes.default.svc";
const DEFAULT_TOKEN_PATH: &str = "/var/run/secrets/kubernetes.io/serviceaccount/token";
const DEFAULT_CA_PATH: &str = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt";

/// The two sentinel schema versions every non-artifact-bearing grant refers
/// to. Seeded by migration 0018; see `no_artifact_schema_versions`.
const NO_ARTIFACT_SCHEMA_VERSION: &str = "00000000-0000-0000-0000-000000000001";
const NO_ARTIFACT_PERMISSION_POLICY_SCHEMA_VERSION: &str = "00000000-0000-0000-0000-000000000002";

#[derive(Debug, Deserialize)]
struct Manifest {
    services: Vec<ServiceSpec>,
}

#[derive(Debug, Deserialize)]
struct ServiceSpec {
    service_id: String,
    /// `service` or `worker`, matching the kernel's own identity kinds.
    kind: String,
    display_name: String,
    /// Omitted for a service that never enrolls -- the policy evaluator
    /// is called *by* the kernel and holds no instance credential of its
    /// own, but still needs an identity row for the foreign keys on
    /// `authority_decisions`.
    #[serde(default)]
    namespace: Option<String>,
    #[serde(default)]
    service_account: Option<String>,
    /// Whether this service may make governed calls at all. Defaults to
    /// false, matching the kernel's own fail-closed default.
    #[serde(default)]
    communication_enabled: bool,
    #[serde(default)]
    grants: Vec<GrantSpec>,
}

#[derive(Debug, Deserialize)]
struct GrantSpec {
    action: String,
    scope: String,
}

#[derive(Debug)]
enum RegistrarError {
    Configuration(String),
    Database(String),
    Kubernetes(String),
    Manifest(String),
}

impl std::fmt::Display for RegistrarError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Configuration(detail) => write!(formatter, "configuration: {detail}"),
            Self::Database(detail) => write!(formatter, "database: {detail}"),
            Self::Kubernetes(detail) => write!(formatter, "kubernetes: {detail}"),
            Self::Manifest(detail) => write!(formatter, "manifest: {detail}"),
        }
    }
}

/// Resolves ServiceAccount UIDs from the Kubernetes API. Kept behind a trait
/// so reconciliation can be exercised without a cluster.
trait ServiceAccountResolver {
    fn uid(&self, namespace: &str, name: &str) -> Result<String, RegistrarError>;
}

struct KubernetesResolver {
    client: HttpClient,
    api_url: String,
    token: String,
}

impl KubernetesResolver {
    fn from_env() -> Result<Self, RegistrarError> {
        let api_url = env::var(API_URL_ENV).unwrap_or_else(|_| DEFAULT_API_URL.to_owned());
        let token_path = env::var(TOKEN_PATH_ENV).unwrap_or_else(|_| DEFAULT_TOKEN_PATH.to_owned());
        let ca_path = env::var(CA_PATH_ENV).unwrap_or_else(|_| DEFAULT_CA_PATH.to_owned());
        let token = fs::read_to_string(&token_path)
            .map_err(|error| RegistrarError::Configuration(format!("{token_path}: {error}")))?
            .trim()
            .to_owned();
        let ca = fs::read(&ca_path)
            .map_err(|error| RegistrarError::Configuration(format!("{ca_path}: {error}")))?;
        let certificate = reqwest::Certificate::from_pem(&ca)
            .map_err(|error| RegistrarError::Configuration(format!("cluster CA: {error}")))?;
        let client = HttpClient::builder()
            .add_root_certificate(certificate)
            .timeout(Duration::from_secs(5))
            .build()
            .map_err(|error| RegistrarError::Configuration(format!("HTTP client: {error}")))?;
        Ok(Self {
            client,
            api_url: api_url.trim_end_matches('/').to_owned(),
            token,
        })
    }
}

impl ServiceAccountResolver for KubernetesResolver {
    fn uid(&self, namespace: &str, name: &str) -> Result<String, RegistrarError> {
        let url = format!(
            "{}/api/v1/namespaces/{namespace}/serviceaccounts/{name}",
            self.api_url
        );
        let response = self
            .client
            .get(&url)
            .bearer_auth(&self.token)
            .send()
            .map_err(|error| RegistrarError::Kubernetes(error.to_string()))?;
        if !response.status().is_success() {
            return Err(RegistrarError::Kubernetes(format!(
                "serviceaccount {namespace}/{name}: HTTP {}",
                response.status()
            )));
        }
        let body: serde_json::Value = response
            .json()
            .map_err(|error| RegistrarError::Kubernetes(error.to_string()))?;
        body.get("metadata")
            .and_then(|metadata| metadata.get("uid"))
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| {
                RegistrarError::Kubernetes(format!(
                    "serviceaccount {namespace}/{name} has no metadata.uid"
                ))
            })
    }
}

/// One reconciliation pass. Returns a per-service tally of what changed, so
/// a repeat run visibly reports nothing.
fn reconcile(
    database: &mut PostgresClient,
    resolver: &dyn ServiceAccountResolver,
    manifest: &Manifest,
    administrator: &str,
) -> Result<BTreeMap<String, Vec<String>>, RegistrarError> {
    let mut changes: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for service in &manifest.services {
        let mut applied = Vec::new();
        let entry_name = service.display_name.clone();

        // Identity. The kernel's own foreign keys hang off this row, so it
        // must exist before anything else referring to the service.
        let rows = database
            .execute(
                "INSERT INTO identities (id, kind, display_name, status) \
                 VALUES ($1::text::uuid, $2, $3, 'active') \
                 ON CONFLICT (id) DO UPDATE \
                 SET display_name = EXCLUDED.display_name, \
                     kind = EXCLUDED.kind, \
                     status = 'active', \
                     updated_at = transaction_timestamp() \
                 WHERE identities.display_name IS DISTINCT FROM EXCLUDED.display_name \
                    OR identities.kind IS DISTINCT FROM EXCLUDED.kind \
                    OR identities.status IS DISTINCT FROM 'active'",
                &[&service.service_id, &service.kind, &service.display_name],
            )
            .map_err(|error| RegistrarError::Database(error.to_string()))?;
        if rows > 0 {
            applied.push("identity".to_owned());
        }

        // Enrollment binding, with the UID resolved from the cluster rather
        // than trusted from the manifest. Skipped entirely for a service
        // that never enrolls.
        if let (Some(namespace), Some(service_account)) = (
            service.namespace.as_deref(),
            service.service_account.as_deref(),
        ) {
            let uid = resolver.uid(namespace, service_account)?;
            let rows = database
                .execute(
                    "INSERT INTO service_enrollment_bindings \
                   (service_id, namespace, service_account, service_account_uid, enabled) \
                 VALUES ($1::text::uuid, $2, $3, $4, true) \
                 ON CONFLICT (service_id) DO UPDATE \
                 SET namespace = EXCLUDED.namespace, \
                     service_account = EXCLUDED.service_account, \
                     service_account_uid = EXCLUDED.service_account_uid, \
                     enabled = true, \
                     updated_at = transaction_timestamp() \
                 WHERE service_enrollment_bindings.service_account_uid \
                         IS DISTINCT FROM EXCLUDED.service_account_uid \
                    OR service_enrollment_bindings.namespace \
                         IS DISTINCT FROM EXCLUDED.namespace \
                    OR service_enrollment_bindings.service_account \
                         IS DISTINCT FROM EXCLUDED.service_account \
                    OR service_enrollment_bindings.enabled IS DISTINCT FROM true",
                    &[&service.service_id, &namespace, &service_account, &uid],
                )
                .map_err(|error| RegistrarError::Database(error.to_string()))?;
            if rows > 0 {
                applied.push(format!("binding -> {uid}"));
            }
        }

        // Communication admission, through the kernel's own constrained
        // procedure so the change is audited rather than written raw.
        let row = database
            .query_one(
                "SELECT (set_service_communication_admission( \
                     $1::text::uuid, $2, $3, $4, gen_random_uuid(), \
                     extract(epoch from now())::bigint)).*",
                &[
                    &service.service_id,
                    &service.communication_enabled,
                    &administrator,
                    &"registrar reconciliation",
                ],
            )
            .map_err(|error| RegistrarError::Database(error.to_string()))?;
        // The procedure reports "changed" or "no_op"; only the former is a
        // real change. Keying off the positive value means an unrecognised
        // outcome is reported rather than silently swallowed.
        let outcome: String = row.get("result_outcome");
        if outcome != "no_op" {
            applied.push(format!(
                "admission={} ({outcome})",
                service.communication_enabled
            ));
        }

        // Grants, also through the constrained procedure. Skipped when an
        // equivalent grant is already live, which is what makes a repeat
        // run a no-op rather than a pile of duplicates.
        for grant in &service.grants {
            let existing = database
                .query_one(
                    "SELECT count(*) FROM authority_grants \
                     WHERE source_service_id = $1::text::uuid \
                       AND action = $2 AND scope = $3 \
                       AND destination_service_id IS NULL \
                       AND revoked_at IS NULL \
                       AND (valid_until IS NULL \
                            OR valid_until > extract(epoch from now())::bigint)",
                    &[&service.service_id, &grant.action, &grant.scope],
                )
                .map_err(|error| RegistrarError::Database(error.to_string()))?;
            let count: i64 = existing.get(0);
            if count > 0 {
                continue;
            }
            database
                .execute(
                    "SELECT create_authority_grant( \
                         gen_random_uuid(), $1::text::uuid, $2, $3, \
                         $4::text::uuid, $5::text::uuid, NULL, 0, NULL, \
                         $6, $7, gen_random_uuid(), \
                         extract(epoch from now())::bigint)",
                    &[
                        &service.service_id,
                        &grant.action,
                        &grant.scope,
                        &NO_ARTIFACT_SCHEMA_VERSION,
                        &NO_ARTIFACT_PERMISSION_POLICY_SCHEMA_VERSION,
                        &administrator,
                        &format!("registrar grant for {}", grant.action),
                    ],
                )
                .map_err(|error| RegistrarError::Database(error.to_string()))?;
            applied.push(format!("grant {} {}", grant.action, grant.scope));
        }

        changes.insert(entry_name, applied);
    }
    Ok(changes)
}

/// Withdraws authority the manifest no longer asks for: enrollment bindings
/// for services it does not mention, and grants it does not list. Disabling
/// a binding stops new instances enrolling but leaves already-enrolled ones
/// running until their lease expires; revoking a grant takes effect on the
/// next authority decision.
fn prune(
    database: &mut PostgresClient,
    manifest: &Manifest,
    administrator: &str,
) -> Result<Vec<String>, RegistrarError> {
    let managed: Vec<String> = manifest
        .services
        .iter()
        .map(|service| service.service_id.clone())
        .collect();
    let mut removed = Vec::new();

    let rows = database
        .query(
            "UPDATE service_enrollment_bindings SET enabled = false, \
                    updated_at = transaction_timestamp() \
             WHERE enabled AND NOT (service_id::text = ANY($1)) \
             RETURNING service_id::text, service_account",
            &[&managed],
        )
        .map_err(|error| RegistrarError::Database(error.to_string()))?;
    for row in &rows {
        let account: String = row.get(1);
        removed.push(format!("binding disabled: {account}"));
    }

    let mut wanted: Vec<(String, String, String)> = Vec::new();
    for service in &manifest.services {
        for grant in &service.grants {
            wanted.push((
                service.service_id.clone(),
                grant.action.clone(),
                grant.scope.clone(),
            ));
        }
    }
    let live = database
        .query(
            "SELECT grant_id::text, source_service_id::text, action, scope \
             FROM authority_grants WHERE revoked_at IS NULL",
            &[],
        )
        .map_err(|error| RegistrarError::Database(error.to_string()))?;
    for row in &live {
        let grant_id: String = row.get(0);
        let source: String = row.get(1);
        let action: String = row.get(2);
        let scope: String = row.get(3);
        if wanted
            .iter()
            .any(|(id, a, s)| id == &source && a == &action && s == &scope)
        {
            continue;
        }
        database
            .execute(
                "SELECT revoke_authority_grant($1::text::uuid, $2, $3, gen_random_uuid(), \
                        extract(epoch from now())::bigint)",
                &[
                    &grant_id,
                    &administrator,
                    &"registrar prune: not present in manifest",
                ],
            )
            .map_err(|error| RegistrarError::Database(error.to_string()))?;
        removed.push(format!("grant revoked: {action} {scope} for {source}"));
    }
    Ok(removed)
}

fn run() -> Result<(), RegistrarError> {
    let database_url = env::var(DATABASE_URL_ENV)
        .map_err(|_| RegistrarError::Configuration(format!("{DATABASE_URL_ENV} is not set")))?;
    let manifest_path = env::var(MANIFEST_PATH_ENV)
        .map_err(|_| RegistrarError::Configuration(format!("{MANIFEST_PATH_ENV} is not set")))?;
    let administrator =
        env::var(ADMINISTRATOR_ENV).unwrap_or_else(|_| "registrar@unattended".to_owned());

    let manifest_text = fs::read_to_string(&manifest_path)
        .map_err(|error| RegistrarError::Manifest(format!("{manifest_path}: {error}")))?;
    let manifest: Manifest = serde_json::from_str(&manifest_text)
        .map_err(|error| RegistrarError::Manifest(error.to_string()))?;

    let mut database = PostgresClient::connect(&database_url, NoTls)
        .map_err(|error| RegistrarError::Database(error.to_string()))?;
    let resolver = KubernetesResolver::from_env()?;

    let prune_enabled = env::var(PRUNE_ENV).is_ok_and(|value| value == "true");
    let changes = reconcile(&mut database, &resolver, &manifest, &administrator)?;
    let mut changed = 0usize;
    for (service, applied) in &changes {
        if applied.is_empty() {
            println!("{service}: already reconciled");
        } else {
            changed += 1;
            println!("{service}: {}", applied.join(", "));
        }
    }
    if prune_enabled {
        let removed = prune(&mut database, &manifest, &administrator)?;
        if removed.is_empty() {
            println!("prune: nothing to withdraw");
        }
        for entry in &removed {
            println!("prune: {entry}");
        }
        println!(
            "reconciled {} service(s), {changed} changed, {} withdrawn",
            changes.len(),
            removed.len()
        );
    } else {
        println!(
            "reconciled {} service(s), {changed} changed (prune disabled; set {PRUNE_ENV}=true to withdraw what the manifest omits)",
            changes.len()
        );
    }
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("registrar failed: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_service_that_never_enrolls_needs_no_kubernetes_binding() {
        let manifest: Manifest = serde_json::from_str(
            r#"{"services":[{"service_id":"00000000-0000-4000-8000-000000000005",
                "kind":"service","display_name":"evaluator"}]}"#,
        )
        .unwrap();
        let service = &manifest.services[0];
        assert!(service.namespace.is_none());
        assert!(service.service_account.is_none());
        // Fail closed: a service is not admitted unless the manifest says so.
        assert!(!service.communication_enabled);
        assert!(service.grants.is_empty());
    }

    #[test]
    fn a_manifest_never_supplies_the_service_account_uid() {
        // The UID is resolved from the cluster precisely so that recreating
        // a ServiceAccount cannot leave a stale binding behind.
        let error = serde_json::from_str::<Manifest>(
            r#"{"services":[{"service_id":"00000000-0000-4000-8000-000000000002",
                "kind":"service","display_name":"taskmaster","namespace":"default",
                "service_account":"taskmaster","service_account_uid":"pinned"}]}"#,
        );
        assert!(error.is_ok(), "unknown fields are ignored, not pinned");
        let manifest = error.unwrap();
        assert_eq!(
            manifest.services[0].service_account.as_deref(),
            Some("taskmaster")
        );
    }

    #[test]
    fn grants_parse_with_action_and_scope() {
        let manifest: Manifest = serde_json::from_str(
            r#"{"services":[{"service_id":"00000000-0000-4000-8000-000000000006",
                "kind":"service","display_name":"librarian","namespace":"default",
                "service_account":"librarian","communication_enabled":true,
                "grants":[{"action":"subscription.create","scope":"*"}]}]}"#,
        )
        .unwrap();
        let service = &manifest.services[0];
        assert!(service.communication_enabled);
        assert_eq!(service.grants.len(), 1);
        assert_eq!(service.grants[0].action, "subscription.create");
        assert_eq!(service.grants[0].scope, "*");
    }
}
