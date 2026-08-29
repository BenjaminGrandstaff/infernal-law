//! Goal: read independently administered communication admission through one
//! fixed query without exposing mutation or caller-supplied SQL to the kernel.

use crate::kernel::admission::{AdmissionError, AdmissionRepository, CommunicationAdmission};
use crate::kernel::identity::ActorId;

use super::database::Database;

#[derive(Clone)]
pub struct PostgresAdmissionRepository {
    database: Database,
}

impl PostgresAdmissionRepository {
    pub const fn new(database: Database) -> Self {
        Self { database }
    }
}

impl AdmissionRepository for PostgresAdmissionRepository {
    fn find(&self, service_id: ActorId) -> Result<Option<CommunicationAdmission>, AdmissionError> {
        let mut connection = self.database.connection().map_err(repository_error)?;
        connection
            .query_opt(
                "SELECT service_id::text, communication_enabled, revision, updated_at \
                 FROM service_communication_admission \
                 WHERE service_id = $1::text::uuid",
                &[&service_id.to_string()],
            )
            .map_err(repository_error)?
            .map(|row| {
                let stored_id = row
                    .get::<_, String>("service_id")
                    .parse::<ActorId>()
                    .map_err(|error| AdmissionError::Repository(error.to_string()))?;
                CommunicationAdmission::restore(
                    stored_id,
                    row.get("communication_enabled"),
                    row.get("revision"),
                    row.get("updated_at"),
                )
            })
            .transpose()
    }
}

fn repository_error(error: impl std::fmt::Display) -> AdmissionError {
    AdmissionError::Repository(error.to_string())
}
