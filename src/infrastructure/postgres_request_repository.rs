//! Goal: atomically persist immutable ILK-003 requests with fixed PostgreSQL
//! statements, idempotent retries, conflict detection, and append-only audit.

use r2d2_postgres::postgres::{Error as PostgresError, Row, Transaction, error::SqlState};

use crate::kernel::authority::{SchemaVersionId, SchemaVersionRefs, Scope};
use crate::kernel::identity::ActorId;
use crate::kernel::requests::{
    AcceptedRequest, Request, RequestAcceptance, RequestError, RequestFingerprint, RequestId,
    RequestRepository,
};

use super::database::Database;

const INSERT_SQL: &str = "INSERT INTO accepted_requests \
    (source_service_id, request_id, action, scope, artifact_schema_version_id, \
     permission_policy_schema_version_id, semantic_fingerprint) \
    VALUES ($1::text::uuid, $2::text::uuid, $3, $4, $5::text::uuid, $6::text::uuid, $7) \
    ON CONFLICT (source_service_id, request_id) DO NOTHING \
    RETURNING source_service_id::text, request_id::text, action, scope, \
              artifact_schema_version_id::text, permission_policy_schema_version_id::text, \
              semantic_fingerprint, \
              EXTRACT(EPOCH FROM accepted_at)::bigint AS accepted_at";
const FIND_SQL: &str = "SELECT source_service_id::text, request_id::text, action, scope, \
        artifact_schema_version_id::text, permission_policy_schema_version_id::text, \
        semantic_fingerprint, \
        EXTRACT(EPOCH FROM accepted_at)::bigint AS accepted_at \
    FROM accepted_requests \
    WHERE source_service_id = $1::text::uuid AND request_id = $2::text::uuid";
const AUDIT_SQL: &str = "INSERT INTO request_acceptance_audit \
    (source_service_id, request_id, attempted_action, attempted_scope, \
     attempted_artifact_schema_version_id, attempted_permission_policy_schema_version_id, \
     attempted_fingerprint, outcome) \
    VALUES ($1::text::uuid, $2::text::uuid, $3, $4, $5::text::uuid, $6::text::uuid, $7, $8)";

#[derive(Clone)]
pub struct PostgresRequestRepository {
    database: Database,
}

impl PostgresRequestRepository {
    pub const fn new(database: Database) -> Self {
        Self { database }
    }
}

impl RequestRepository for PostgresRequestRepository {
    fn accept(
        &self,
        request: Request,
        fingerprint: RequestFingerprint,
    ) -> Result<RequestAcceptance, RequestError> {
        let mut connection = self.database.connection().map_err(repository_error)?;
        let mut transaction = connection.transaction().map_err(repository_error)?;
        let source_service = request.source_service().to_string();
        let request_id = request.id().to_string();
        let action = request.action().as_str();
        let scope = request.scope().as_str();
        let artifact_schema_version_id = request.schema_versions().artifact().to_string();
        let permission_policy_schema_version_id =
            request.schema_versions().permission_policy().to_string();
        let fingerprint_bytes = fingerprint.as_bytes().as_slice();

        let inserted = transaction.query_opt(
            INSERT_SQL,
            &[
                &source_service,
                &request_id,
                &action,
                &scope,
                &artifact_schema_version_id,
                &permission_policy_schema_version_id,
                &fingerprint_bytes,
            ],
        );
        let inserted = match inserted {
            Ok(value) => value,
            Err(error) => {
                return Err(
                    foreign_key_violation_error(&error, request.source_service())
                        .unwrap_or_else(|| repository_error(error)),
                );
            }
        };

        if let Some(row) = inserted {
            let stored = accepted_request_from_row(&row)?;
            append_audit(&mut transaction, &request, fingerprint, "accepted")?;
            transaction.commit().map_err(repository_error)?;
            return Ok(RequestAcceptance::Accepted(stored));
        }

        let row = transaction
            .query_opt(FIND_SQL, &[&source_service, &request_id])
            .map_err(repository_error)?
            .ok_or_else(|| {
                RequestError::Repository(
                    "conflicting request disappeared during acceptance".to_owned(),
                )
            })?;
        let stored = accepted_request_from_row(&row)?;
        if stored.request() != &request || stored.fingerprint() != fingerprint {
            append_audit(
                &mut transaction,
                &request,
                fingerprint,
                "request_conflict_rejected",
            )?;
            transaction.commit().map_err(repository_error)?;
            return Err(RequestError::RequestIdConflict(request.id()));
        }

        append_audit(&mut transaction, &request, fingerprint, "safe_retry")?;
        transaction.commit().map_err(repository_error)?;
        Ok(RequestAcceptance::SafeRetry(stored))
    }

    fn find(
        &self,
        source_service: ActorId,
        request_id: RequestId,
    ) -> Result<Option<AcceptedRequest>, RequestError> {
        let mut connection = self.database.connection().map_err(repository_error)?;
        connection
            .query_opt(
                FIND_SQL,
                &[&source_service.to_string(), &request_id.to_string()],
            )
            .map_err(repository_error)?
            .as_ref()
            .map(accepted_request_from_row)
            .transpose()
    }
}

fn append_audit(
    transaction: &mut Transaction<'_>,
    request: &Request,
    fingerprint: RequestFingerprint,
    outcome: &str,
) -> Result<(), RequestError> {
    let rows = transaction
        .execute(
            AUDIT_SQL,
            &[
                &request.source_service().to_string(),
                &request.id().to_string(),
                &request.action().as_str(),
                &request.scope().as_str(),
                &request.schema_versions().artifact().to_string(),
                &request.schema_versions().permission_policy().to_string(),
                &fingerprint.as_bytes().as_slice(),
                &outcome,
            ],
        )
        .map_err(repository_error)?;
    if rows != 1 {
        return Err(RequestError::Repository(format!(
            "request acceptance audit changed {rows} rows"
        )));
    }
    Ok(())
}

fn accepted_request_from_row(row: &Row) -> Result<AcceptedRequest, RequestError> {
    let source_service = row
        .get::<_, String>("source_service_id")
        .parse::<ActorId>()
        .map_err(|error| RequestError::Repository(format!("invalid stored source ID: {error}")))?;
    let request_id = row.get::<_, String>("request_id").parse::<RequestId>()?;
    let scope = Scope::new(row.get("scope"))
        .map_err(|_| RequestError::Repository("stored request scope is invalid".to_owned()))?;
    let artifact_schema_version_id = row
        .get::<_, String>("artifact_schema_version_id")
        .parse::<SchemaVersionId>()
        .map_err(|_| {
            RequestError::Repository("stored artifact schema version ID is invalid".to_owned())
        })?;
    let permission_policy_schema_version_id = row
        .get::<_, String>("permission_policy_schema_version_id")
        .parse::<SchemaVersionId>()
        .map_err(|_| {
            RequestError::Repository(
                "stored permission-policy schema version ID is invalid".to_owned(),
            )
        })?;
    let schema_versions = SchemaVersionRefs::new(
        artifact_schema_version_id,
        permission_policy_schema_version_id,
    );
    let request = Request::restore(
        request_id,
        source_service,
        row.get("action"),
        scope,
        schema_versions,
    )
    .map_err(|_| RequestError::Repository("stored request action is invalid".to_owned()))?;
    let fingerprint: Vec<u8> = row.get("semantic_fingerprint");
    let fingerprint: [u8; 32] = fingerprint.try_into().map_err(|_| {
        RequestError::Repository("stored request fingerprint is invalid".to_owned())
    })?;
    AcceptedRequest::restore(
        request,
        RequestFingerprint::from_bytes(fingerprint),
        row.get("accepted_at"),
    )
    .map_err(|_| RequestError::Repository("stored acceptance time is invalid".to_owned()))
}

/// Maps an INSERT's foreign-key violation to the specific reference that
/// failed, rather than assuming it was always the source -- `accepted_requests`
/// now also foreign-keys both schema version columns, and conflating "unknown
/// source" with "unknown schema version" would misreport a perfectly valid
/// caller as unauthenticated.
fn foreign_key_violation_error(
    error: &PostgresError,
    source_service: ActorId,
) -> Option<RequestError> {
    let db_error = error.as_db_error()?;
    if db_error.code() != &SqlState::FOREIGN_KEY_VIOLATION {
        return None;
    }
    match db_error.constraint() {
        Some("accepted_requests_source_service_id_fkey") => {
            Some(RequestError::UnknownSource(source_service))
        }
        Some(
            "accepted_requests_artifact_schema_version_fk"
            | "accepted_requests_permission_policy_schema_version_fk",
        ) => Some(RequestError::UnknownSchemaVersion),
        _ => None,
    }
}

fn repository_error(error: impl std::fmt::Display) -> RequestError {
    RequestError::Repository(error.to_string())
}
