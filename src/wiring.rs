//! Goal: construct the process-wide adapters and kernel services in one place
//! so transports receive ready-to-use dependencies rather than creating them.

use std::env;
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::sync::Arc;

use crate::infrastructure::database::{Database, DatabaseError};
use crate::infrastructure::postgres_enrollment_binding_repository::PostgresEnrollmentBindingRepository;
use crate::infrastructure::postgres_identity_repository::PostgresIdentityRepository;
use crate::infrastructure::postgres_instance_registry::PostgresInstanceRegistry;
use crate::kernel::enrollment::{EnrollmentService, WorkloadTokenReviewer};
use crate::kernel::identity::{ActorId, IdentityService};
use crate::kernel::instance_keys::{InstanceCredential, InstancePublicKey, InstanceSignature};
use crate::kernel::instance_registry::{InstanceRegistryService, LeasePolicy};

pub const SERVICE_ID_ENV: &str = "INFERNAL_LAW_SERVICE_ID";

#[derive(Clone)]
pub struct Application {
    database: Database,
    identities: IdentityService<PostgresIdentityRepository>,
    instance_credential: Arc<InstanceCredential>,
    instance_registry: InstanceRegistryService<PostgresInstanceRegistry>,
}

impl Application {
    pub fn from_env() -> Result<Self, WiringError> {
        let service_id = env::var(SERVICE_ID_ENV)
            .map_err(|_| WiringError::MissingEnvironment(SERVICE_ID_ENV))?
            .parse()
            .map_err(WiringError::InvalidServiceId)?;
        Self::new(Database::connect_from_env()?, service_id)
    }

    pub fn new(database: Database, service_id: ActorId) -> Result<Self, WiringError> {
        database.migrate()?;
        let identities = IdentityService::new(PostgresIdentityRepository::new(database.clone()));
        let instance_credential = Arc::new(InstanceCredential::generate(service_id));
        let instance_registry = InstanceRegistryService::new(
            PostgresInstanceRegistry::new(database.clone()),
            LeasePolicy::default(),
        );

        Ok(Self {
            database,
            identities,
            instance_credential,
            instance_registry,
        })
    }

    pub const fn database(&self) -> &Database {
        &self.database
    }

    pub const fn identities(&self) -> &IdentityService<PostgresIdentityRepository> {
        &self.identities
    }

    pub fn instance_public_key(&self) -> &InstancePublicKey {
        self.instance_credential.public_key()
    }

    pub fn sign_as_instance(&self, message: &[u8]) -> InstanceSignature {
        self.instance_credential.sign(message)
    }

    pub const fn instance_registry(&self) -> &InstanceRegistryService<PostgresInstanceRegistry> {
        &self.instance_registry
    }

    pub fn enrollment_service<A>(
        &self,
        reviewer: A,
    ) -> EnrollmentService<A, PostgresEnrollmentBindingRepository, PostgresInstanceRegistry>
    where
        A: WorkloadTokenReviewer,
    {
        EnrollmentService::new(
            reviewer,
            PostgresEnrollmentBindingRepository::new(self.database.clone()),
            self.instance_registry.clone(),
        )
    }
}

#[derive(Debug)]
pub enum WiringError {
    Database(DatabaseError),
    InvalidServiceId(crate::kernel::identity::IdentityError),
    MissingEnvironment(&'static str),
}

impl Display for WiringError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(error) => Display::fmt(error, formatter),
            Self::InvalidServiceId(error) => Display::fmt(error, formatter),
            Self::MissingEnvironment(name) => {
                write!(formatter, "required environment variable {name} is not set")
            }
        }
    }
}

impl Error for WiringError {}

impl From<DatabaseError> for WiringError {
    fn from(value: DatabaseError) -> Self {
        Self::Database(value)
    }
}
