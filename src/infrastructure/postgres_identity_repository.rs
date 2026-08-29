//! Goal: persist ILK-001 identities in PostgreSQL while keeping SQL and
//! database error translation outside the identity domain module.

use r2d2_postgres::postgres::{Error as PostgresError, Row, error::SqlState};

use crate::kernel::identity::{
    ActorId, ActorKind, Identity, IdentityError, IdentityRepository, IdentityStatus,
};

use super::database::Database;

#[derive(Clone)]
pub struct PostgresIdentityRepository {
    database: Database,
}

impl PostgresIdentityRepository {
    pub const fn new(database: Database) -> Self {
        Self { database }
    }
}

impl IdentityRepository for PostgresIdentityRepository {
    fn insert(&self, identity: Identity) -> Result<(), IdentityError> {
        let mut connection = self.database.connection().map_err(repository_error)?;
        let id = identity.id().to_string();
        let result = connection.execute(
            "INSERT INTO identities (id, kind, display_name, status) \
             VALUES ($1::text::uuid, $2, $3, $4)",
            &[
                &id,
                &identity.kind().as_str(),
                &identity.display_name(),
                &identity.status().as_str(),
            ],
        );

        match result {
            Ok(1) => Ok(()),
            Ok(rows) => Err(IdentityError::Repository(format!(
                "identity insert changed {rows} rows"
            ))),
            Err(error) if is_unique_violation(&error) => {
                Err(IdentityError::AlreadyExists(identity.id()))
            }
            Err(error) => Err(repository_error(error)),
        }
    }

    fn find(&self, id: ActorId) -> Result<Option<Identity>, IdentityError> {
        let mut connection = self.database.connection().map_err(repository_error)?;
        let id_text = id.to_string();
        let row = connection
            .query_opt(
                "SELECT id::text AS id, kind, display_name, status \
                 FROM identities WHERE id = $1::text::uuid",
                &[&id_text],
            )
            .map_err(repository_error)?;

        row.as_ref().map(identity_from_row).transpose()
    }

    fn save(&self, identity: Identity) -> Result<(), IdentityError> {
        let mut connection = self.database.connection().map_err(repository_error)?;
        let id = identity.id().to_string();
        let rows = connection
            .execute(
                "UPDATE identities \
                 SET kind = $2, display_name = $3, status = $4, \
                     updated_at = transaction_timestamp() \
                 WHERE id = $1::text::uuid",
                &[
                    &id,
                    &identity.kind().as_str(),
                    &identity.display_name(),
                    &identity.status().as_str(),
                ],
            )
            .map_err(repository_error)?;

        match rows {
            1 => Ok(()),
            0 => Err(IdentityError::NotFound(identity.id())),
            rows => Err(IdentityError::Repository(format!(
                "identity update changed {rows} rows"
            ))),
        }
    }
}

fn identity_from_row(row: &Row) -> Result<Identity, IdentityError> {
    let id = row.get::<_, String>("id").parse::<ActorId>()?;
    let kind = row.get::<_, String>("kind").parse::<ActorKind>()?;
    let status = row.get::<_, String>("status").parse::<IdentityStatus>()?;
    let display_name = row.get::<_, String>("display_name");

    Identity::restore(id, kind, &display_name, status)
}

fn is_unique_violation(error: &PostgresError) -> bool {
    error
        .as_db_error()
        .is_some_and(|error| error.code() == &SqlState::UNIQUE_VIOLATION)
}

fn repository_error(error: impl std::fmt::Display) -> IdentityError {
    IdentityError::Repository(error.to_string())
}
