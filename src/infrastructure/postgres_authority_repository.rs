//! Goal: read kernel-owned ILK-002 authority grants from PostgreSQL for the
//! `AuthorityRepository` contract. Grant administration happens only through
//! the out-of-band `create_authority_grant` database function, never through
//! this adapter — the same split already used for communication admission.

use r2d2_postgres::postgres::Row;

use crate::kernel::authority::{
    AuthorityError, AuthorityRepository, Grant, GrantId, PolicyFacts, Scope,
};
use crate::kernel::identity::ActorId;
use crate::kernel::requests::ActionName;

use super::database::Database;

const MATCHING_GRANTS_SQL: &str = "SELECT grant_id::text, source_service_id::text, action, \
        scope, destination_service_id::text, valid_from, valid_until \
    FROM authority_grants \
    WHERE source_service_id = $1::text::uuid \
      AND action = $2 \
      AND destination_service_id IS NOT DISTINCT FROM $3::text::uuid \
      AND (scope = '*' OR scope = $4) \
      AND valid_from <= $5 \
      AND (valid_until IS NULL OR valid_until > $5)";

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
        let rows = connection
            .query(
                MATCHING_GRANTS_SQL,
                &[
                    &facts.source().to_string(),
                    &facts.action().as_str(),
                    &destination,
                    &facts.scope().as_str(),
                    &now,
                ],
            )
            .map_err(repository_error)?;
        rows.iter().map(grant_from_row).collect()
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
        destination,
        row.get("valid_from"),
        row.get("valid_until"),
    )
}

fn repository_error(error: impl std::fmt::Display) -> AuthorityError {
    AuthorityError::Repository(error.to_string())
}
