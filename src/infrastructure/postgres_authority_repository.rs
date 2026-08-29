//! Goal: read kernel-owned ILK-002 authority grants and schema versions from
//! PostgreSQL, and durably record pinned decisions. Grant creation and
//! schema status administration happen only through out-of-band database
//! functions, never through this adapter — the same split already used for
//! communication admission. Schema publication and decision recording are
//! the two write paths this adapter does call directly: publication because
//! any authenticated service may publish a schema it owns, and decision
//! recording because it is kernel bookkeeping, not administration.

use r2d2_postgres::postgres::Row;

use crate::kernel::authority::{
    AuthorityDecision, AuthorityDecisionRecorder, AuthorityError, AuthorityRepository,
    ContentDigest, Grant, GrantId, PolicyFacts, SchemaKind, SchemaName, SchemaRecord,
    SchemaRepository, SchemaStatus, SchemaVersion, SchemaVersionId, SchemaVersionRefs, Scope,
    Verdict,
};
use crate::kernel::identity::ActorId;
use crate::kernel::requests::ActionName;

use super::database::Database;

const MATCHING_GRANTS_SQL: &str = "SELECT grant_id::text, source_service_id::text, action, \
        scope, artifact_schema_version_id::text, permission_policy_schema_version_id::text, \
        destination_service_id::text, valid_from, valid_until \
    FROM authority_grants \
    WHERE source_service_id = $1::text::uuid \
      AND action = $2 \
      AND artifact_schema_version_id = $3::text::uuid \
      AND permission_policy_schema_version_id = $4::text::uuid \
      AND destination_service_id IS NOT DISTINCT FROM $5::text::uuid \
      AND (scope = '*' OR scope = $6) \
      AND valid_from <= $7 \
      AND (valid_until IS NULL OR valid_until > $7)";

const PUBLISH_SCHEMA_VERSION_SQL: &str = "SELECT * FROM publish_authority_schema_version( \
    $1::text::uuid, $2, $3, $4::text::uuid, $5, $6)";

const FIND_SCHEMA_VERSION_SQL: &str = "SELECT schema_version_id::text, kind, name, version, \
        owner_service_id::text, content_digest, predecessor_id::text, published_at, status \
    FROM authority_schema_versions \
    WHERE kind = $1 AND name = $2 AND version = $3";

const RECORD_DECISION_SQL: &str = "INSERT INTO authority_decisions \
    (decision_id, source_service_id, action, scope, \
     artifact_schema_version_id, permission_policy_schema_version_id, \
     destination_service_id, verdict, evaluator_service_id, policy_bundle_version, decided_at) \
    VALUES ($1::text::uuid, $2::text::uuid, $3, $4, $5::text::uuid, $6::text::uuid, \
            $7::text::uuid, $8, $9::text::uuid, $10, $11)";

#[derive(Clone)]
pub struct PostgresAuthorityRepository {
    database: Database,
}

impl PostgresAuthorityRepository {
    pub const fn new(database: Database) -> Self {
        Self { database }
    }
}

impl AuthorityRepository for PostgresAuthorityRepository {
    fn matching_grants(&self, facts: &PolicyFacts, now: i64) -> Result<Vec<Grant>, AuthorityError> {
        let mut connection = self.database.connection().map_err(repository_error)?;
        let destination = facts.destination().map(|id| id.to_string());
        let schema_versions = facts.schema_versions();
        let rows = connection
            .query(
                MATCHING_GRANTS_SQL,
                &[
                    &facts.source().to_string(),
                    &facts.action().as_str(),
                    &schema_versions.artifact().to_string(),
                    &schema_versions.permission_policy().to_string(),
                    &destination,
                    &facts.scope().as_str(),
                    &now,
                ],
            )
            .map_err(repository_error)?;
        rows.iter().map(grant_from_row).collect()
    }
}

impl SchemaRepository for PostgresAuthorityRepository {
    fn publish(
        &self,
        kind: SchemaKind,
        name: SchemaName,
        owner: ActorId,
        content_digest: ContentDigest,
        published_at: i64,
    ) -> Result<SchemaRecord, AuthorityError> {
        let mut connection = self.database.connection().map_err(repository_error)?;
        let row = connection
            .query_one(
                PUBLISH_SCHEMA_VERSION_SQL,
                &[
                    &SchemaVersionId::new().to_string(),
                    &schema_kind_to_sql(kind),
                    &name.as_str(),
                    &owner.to_string(),
                    &content_digest.as_bytes().as_slice(),
                    &published_at,
                ],
            )
            .map_err(repository_error)?;
        schema_record_from_row(&row)
    }

    fn find(
        &self,
        kind: SchemaKind,
        name: &SchemaName,
        version: i64,
    ) -> Result<Option<SchemaRecord>, AuthorityError> {
        let mut connection = self.database.connection().map_err(repository_error)?;
        connection
            .query_opt(
                FIND_SCHEMA_VERSION_SQL,
                &[&schema_kind_to_sql(kind), &name.as_str(), &version],
            )
            .map_err(repository_error)?
            .as_ref()
            .map(schema_record_from_row)
            .transpose()
    }
}

impl AuthorityDecisionRecorder for PostgresAuthorityRepository {
    fn record(&self, decision: &AuthorityDecision) -> Result<(), AuthorityError> {
        let mut connection = self.database.connection().map_err(repository_error)?;
        let facts = decision.facts();
        let schema_versions = facts.schema_versions();
        let destination = facts.destination().map(|id| id.to_string());
        let policy_bundle_version = decision
            .policy_bundle_version()
            .map(|version| version.as_str());
        let rows = connection
            .execute(
                RECORD_DECISION_SQL,
                &[
                    &decision.id().to_string(),
                    &facts.source().to_string(),
                    &facts.action().as_str(),
                    &facts.scope().as_str(),
                    &schema_versions.artifact().to_string(),
                    &schema_versions.permission_policy().to_string(),
                    &destination,
                    &verdict_to_sql(decision.verdict()),
                    &decision.evaluator().to_string(),
                    &policy_bundle_version,
                    &decision.decided_at(),
                ],
            )
            .map_err(repository_error)?;
        if rows != 1 {
            return Err(AuthorityError::Repository(format!(
                "recording decision {} changed {rows} rows",
                decision.id()
            )));
        }
        Ok(())
    }
}

fn grant_from_row(row: &Row) -> Result<Grant, AuthorityError> {
    let id = row.get::<_, String>("grant_id").parse::<GrantId>()?;
    let source = row
        .get::<_, String>("source_service_id")
        .parse::<ActorId>()
        .map_err(|error| {
            AuthorityError::Repository(format!("invalid stored source ID: {error}"))
        })?;
    let action = ActionName::new(&row.get::<_, String>("action"))
        .map_err(|_| AuthorityError::Repository("stored grant action is invalid".to_owned()))?;
    let scope = Scope::new(&row.get::<_, String>("scope"))
        .map_err(|_| AuthorityError::Repository("stored grant scope is invalid".to_owned()))?;
    let artifact_schema_version = row
        .get::<_, String>("artifact_schema_version_id")
        .parse::<SchemaVersionId>()?;
    let permission_policy_schema_version = row
        .get::<_, String>("permission_policy_schema_version_id")
        .parse::<SchemaVersionId>()?;
    let destination = row
        .get::<_, Option<String>>("destination_service_id")
        .map(|value| value.parse::<ActorId>())
        .transpose()
        .map_err(|error| {
            AuthorityError::Repository(format!("invalid stored destination ID: {error}"))
        })?;
    Grant::restore(
        id,
        source,
        action,
        scope,
        SchemaVersionRefs::new(artifact_schema_version, permission_policy_schema_version),
        destination,
        row.get("valid_from"),
        row.get("valid_until"),
    )
}

fn schema_record_from_row(row: &Row) -> Result<SchemaRecord, AuthorityError> {
    let id = row
        .get::<_, String>("schema_version_id")
        .parse::<SchemaVersionId>()?;
    let kind = schema_kind_from_sql(&row.get::<_, String>("kind"))?;
    let name = SchemaName::new(&row.get::<_, String>("name"))
        .map_err(|_| AuthorityError::Repository("stored schema name is invalid".to_owned()))?;
    let owner = row
        .get::<_, String>("owner_service_id")
        .parse::<ActorId>()
        .map_err(|error| AuthorityError::Repository(format!("invalid stored owner ID: {error}")))?;
    let content_digest: Vec<u8> = row.get("content_digest");
    let content_digest: [u8; 32] = content_digest
        .try_into()
        .map_err(|_| AuthorityError::Repository("stored content digest is invalid".to_owned()))?;
    let predecessor = row
        .get::<_, Option<String>>("predecessor_id")
        .map(|value| value.parse::<SchemaVersionId>())
        .transpose()?;
    let version = SchemaVersion::restore(
        id,
        kind,
        name,
        row.get("version"),
        owner,
        ContentDigest::from_bytes(content_digest),
        predecessor,
        row.get("published_at"),
    )?;
    let status = schema_status_from_sql(&row.get::<_, String>("status"))?;
    Ok(SchemaRecord::restore(version, status))
}

fn verdict_to_sql(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Allow => "allow",
        Verdict::Deny => "deny",
    }
}

fn schema_kind_to_sql(kind: SchemaKind) -> &'static str {
    match kind {
        SchemaKind::Artifact => "artifact",
        SchemaKind::PermissionPolicy => "permission_policy",
    }
}

fn schema_kind_from_sql(value: &str) -> Result<SchemaKind, AuthorityError> {
    match value {
        "artifact" => Ok(SchemaKind::Artifact),
        "permission_policy" => Ok(SchemaKind::PermissionPolicy),
        other => Err(AuthorityError::Repository(format!(
            "unknown stored schema kind: {other}"
        ))),
    }
}

fn schema_status_from_sql(value: &str) -> Result<SchemaStatus, AuthorityError> {
    match value {
        "published" => Ok(SchemaStatus::Published),
        "active" => Ok(SchemaStatus::Active),
        "suspended" => Ok(SchemaStatus::Suspended),
        "superseded" => Ok(SchemaStatus::Superseded),
        "retired" => Ok(SchemaStatus::Retired),
        other => Err(AuthorityError::Repository(format!(
            "unknown stored schema status: {other}"
        ))),
    }
}

fn repository_error(error: impl std::fmt::Display) -> AuthorityError {
    AuthorityError::Repository(error.to_string())
}
