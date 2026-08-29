//! Goal: construct the process-wide adapters and kernel services in one place
//! so transports receive ready-to-use dependencies rather than creating them.

use crate::infrastructure::database::{Database, DatabaseError};
use crate::infrastructure::postgres_identity_repository::PostgresIdentityRepository;
use crate::kernel::identity::IdentityService;

#[derive(Clone)]
pub struct Application {
    database: Database,
    identities: IdentityService<PostgresIdentityRepository>,
}

impl Application {
    pub fn from_env() -> Result<Self, DatabaseError> {
        Self::new(Database::connect_from_env()?)
    }

    pub fn new(database: Database) -> Result<Self, DatabaseError> {
        database.migrate()?;
        let identities = IdentityService::new(PostgresIdentityRepository::new(database.clone()));

        Ok(Self {
            database,
            identities,
        })
    }

    pub const fn database(&self) -> &Database {
        &self.database
    }

    pub const fn identities(&self) -> &IdentityService<PostgresIdentityRepository> {
        &self.identities
    }
}
