//! Goal: construct the process-wide adapters and kernel services in one place
//! so transports receive ready-to-use dependencies rather than creating them.

use std::env;
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::sync::Arc;

use crate::infrastructure::database::{Database, DatabaseError};
use crate::infrastructure::postgres_admission_repository::PostgresAdmissionRepository;
use crate::infrastructure::postgres_enrollment_binding_repository::PostgresEnrollmentBindingRepository;
use crate::infrastructure::postgres_handshake_repository::PostgresHandshakeRepository;
use crate::infrastructure::postgres_identity_repository::PostgresIdentityRepository;
use crate::infrastructure::postgres_instance_registry::PostgresInstanceRegistry;
use crate::infrastructure::postgres_replay_protection_repository::PostgresReplayProtectionRepository;
use crate::infrastructure::postgres_subscribed_instance_discovery::PostgresSubscribedInstanceDiscovery;
use crate::infrastructure::postgres_subscription_repository::PostgresSubscriptionRepository;
use crate::kernel::admission::AdmissionService;
use crate::kernel::enrollment::{EnrollmentService, WorkloadTokenReviewer};
use crate::kernel::handshakes::{HandshakeReconciler, HandshakeTransport};
use crate::kernel::identity::{ActorId, IdentityService};
use crate::kernel::instance_keys::{InstanceCredential, InstancePublicKey, InstanceSignature};
use crate::kernel::instance_registry::{InstanceRegistryService, LeasePolicy};
use crate::kernel::replay_protection::ReplayProtectionService;
use crate::kernel::request_gate::ServiceRequestGate;
use crate::kernel::service_requests::ServiceRequestVerifier;
use crate::kernel::subscriptions::SubscriptionService;

pub const SERVICE_ID_ENV: &str = "INFERNAL_LAW_SERVICE_ID";

#[derive(Clone)]
pub struct Application {
    database: Database,
    admission: AdmissionService<PostgresAdmissionRepository>,
    identities: IdentityService<PostgresIdentityRepository>,
    instance_credential: Arc<InstanceCredential>,
    instance_registry: InstanceRegistryService<PostgresInstanceRegistry>,
    subscriptions: SubscriptionService<PostgresSubscriptionRepository>,
    replay_protection: ReplayProtectionService<PostgresReplayProtectionRepository>,
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
        let admission = AdmissionService::new(PostgresAdmissionRepository::new(database.clone()));
        let instance_credential = Arc::new(InstanceCredential::generate(service_id));
        let instance_registry = InstanceRegistryService::new(
            PostgresInstanceRegistry::new(database.clone()),
            LeasePolicy::default(),
        );
        let subscriptions =
            SubscriptionService::new(PostgresSubscriptionRepository::new(database.clone()));
        let replay_protection =
            ReplayProtectionService::new(PostgresReplayProtectionRepository::new(database.clone()));

        Ok(Self {
            database,
            admission,
            identities,
            instance_credential,
            instance_registry,
            subscriptions,
            replay_protection,
        })
    }

    pub const fn database(&self) -> &Database {
        &self.database
    }

    pub const fn admission(&self) -> &AdmissionService<PostgresAdmissionRepository> {
        &self.admission
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

    pub fn service_request_verifier(
        &self,
    ) -> ServiceRequestVerifier<InstanceRegistryService<PostgresInstanceRegistry>> {
        ServiceRequestVerifier::new(self.instance_registry.clone())
    }

    pub fn service_request_gate(
        &self,
    ) -> ServiceRequestGate<
        ServiceRequestVerifier<InstanceRegistryService<PostgresInstanceRegistry>>,
        ReplayProtectionService<PostgresReplayProtectionRepository>,
        AdmissionService<PostgresAdmissionRepository>,
    > {
        ServiceRequestGate::new(
            self.service_request_verifier(),
            self.replay_protection.clone(),
            self.admission.clone(),
        )
    }

    pub const fn subscriptions(&self) -> &SubscriptionService<PostgresSubscriptionRepository> {
        &self.subscriptions
    }

    pub const fn replay_protection(
        &self,
    ) -> &ReplayProtectionService<PostgresReplayProtectionRepository> {
        &self.replay_protection
    }

    pub fn handshake_reconciler<T>(
        &self,
        transport: T,
    ) -> HandshakeReconciler<PostgresSubscribedInstanceDiscovery, PostgresHandshakeRepository, T>
    where
        T: HandshakeTransport,
    {
        HandshakeReconciler::new(
            self.instance_credential.clone(),
            PostgresSubscribedInstanceDiscovery::new(self.database.clone()),
            PostgresHandshakeRepository::new(self.database.clone()),
            transport,
        )
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
