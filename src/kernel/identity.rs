//! Goal: implement ILK-001 so every service and worker operation is
//! attributable to a stable service identity.

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

use uuid::Uuid;

use super::Requirement;

pub const REQUIREMENT: Requirement = Requirement::new(
    "ILK-001",
    "Identity",
    "Every calling service and worker has a stable service identity.",
);

pub const MAX_DISPLAY_NAME_LENGTH: usize = 200;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ActorId(Uuid);

impl ActorId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    pub const fn from_uuid(value: Uuid) -> Self {
        Self(value)
    }

    pub const fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

impl Default for ActorId {
    fn default() -> Self {
        Self::new()
    }
}

impl Display for ActorId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.0, formatter)
    }
}

impl FromStr for ActorId {
    type Err = IdentityError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(value)
            .map(Self)
            .map_err(|_| IdentityError::InvalidActorId)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActorKind {
    Service,
    Worker,
}

impl ActorKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Service => "service",
            Self::Worker => "worker",
        }
    }
}

impl FromStr for ActorKind {
    type Err = IdentityError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "service" => Ok(Self::Service),
            "worker" => Ok(Self::Worker),
            value => Err(IdentityError::InvalidActorKind(value.to_owned())),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityStatus {
    Active,
    Disabled,
}

impl IdentityStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Disabled => "disabled",
        }
    }
}

impl FromStr for IdentityStatus {
    type Err = IdentityError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "active" => Ok(Self::Active),
            "disabled" => Ok(Self::Disabled),
            value => Err(IdentityError::InvalidIdentityStatus(value.to_owned())),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Identity {
    id: ActorId,
    kind: ActorKind,
    display_name: String,
    status: IdentityStatus,
}

impl Identity {
    fn create(id: ActorId, kind: ActorKind, display_name: &str) -> Result<Self, IdentityError> {
        Ok(Self {
            id,
            kind,
            display_name: validate_display_name(display_name)?,
            status: IdentityStatus::Active,
        })
    }

    pub fn restore(
        id: ActorId,
        kind: ActorKind,
        display_name: &str,
        status: IdentityStatus,
    ) -> Result<Self, IdentityError> {
        Ok(Self {
            id,
            kind,
            display_name: validate_display_name(display_name)?,
            status,
        })
    }

    pub const fn id(&self) -> ActorId {
        self.id
    }

    pub const fn kind(&self) -> ActorKind {
        self.kind
    }

    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    pub const fn status(&self) -> IdentityStatus {
        self.status
    }

    pub const fn is_active(&self) -> bool {
        matches!(self.status, IdentityStatus::Active)
    }

    fn rename(&mut self, display_name: &str) -> Result<(), IdentityError> {
        self.display_name = validate_display_name(display_name)?;
        Ok(())
    }

    fn disable(&mut self) {
        self.status = IdentityStatus::Disabled;
    }
}

fn validate_display_name(display_name: &str) -> Result<String, IdentityError> {
    let display_name = display_name.trim();
    if display_name.is_empty() || display_name.chars().count() > MAX_DISPLAY_NAME_LENGTH {
        return Err(IdentityError::InvalidDisplayName);
    }

    Ok(display_name.to_owned())
}

pub trait IdentityRepository: Send + Sync {
    fn insert(&self, identity: Identity) -> Result<(), IdentityError>;
    fn find(&self, id: ActorId) -> Result<Option<Identity>, IdentityError>;
    fn save(&self, identity: Identity) -> Result<(), IdentityError>;
}

#[derive(Clone)]
pub struct IdentityService<R> {
    repository: R,
}

impl<R> IdentityService<R>
where
    R: IdentityRepository,
{
    pub const fn new(repository: R) -> Self {
        Self { repository }
    }

    pub fn create(&self, kind: ActorKind, display_name: &str) -> Result<Identity, IdentityError> {
        let identity = Identity::create(ActorId::new(), kind, display_name)?;
        self.repository.insert(identity.clone())?;
        Ok(identity)
    }

    pub fn find(&self, id: ActorId) -> Result<Option<Identity>, IdentityError> {
        self.repository.find(id)
    }

    pub fn resolve_active(&self, id: ActorId) -> Result<Identity, IdentityError> {
        let identity = self.find_required(id)?;
        if !identity.is_active() {
            return Err(IdentityError::Disabled(id));
        }

        Ok(identity)
    }

    pub fn rename(&self, id: ActorId, display_name: &str) -> Result<Identity, IdentityError> {
        let mut identity = self.find_required(id)?;
        identity.rename(display_name)?;
        self.repository.save(identity.clone())?;
        Ok(identity)
    }

    pub fn disable(&self, id: ActorId) -> Result<Identity, IdentityError> {
        let mut identity = self.find_required(id)?;
        identity.disable();
        self.repository.save(identity.clone())?;
        Ok(identity)
    }

    fn find_required(&self, id: ActorId) -> Result<Identity, IdentityError> {
        self.repository.find(id)?.ok_or(IdentityError::NotFound(id))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IdentityError {
    AlreadyExists(ActorId),
    Disabled(ActorId),
    InvalidActorId,
    InvalidActorKind(String),
    InvalidDisplayName,
    InvalidIdentityStatus(String),
    NotFound(ActorId),
    Repository(String),
}

impl Display for IdentityError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyExists(id) => write!(formatter, "identity {id} already exists"),
            Self::Disabled(id) => write!(formatter, "identity {id} is disabled"),
            Self::InvalidActorId => formatter.write_str("service ID must be a valid UUID"),
            Self::InvalidActorKind(value) => write!(formatter, "invalid service kind '{value}'"),
            Self::InvalidDisplayName => write!(
                formatter,
                "display name must contain 1 to {MAX_DISPLAY_NAME_LENGTH} characters"
            ),
            Self::InvalidIdentityStatus(value) => {
                write!(formatter, "invalid identity status '{value}'")
            }
            Self::NotFound(id) => write!(formatter, "identity {id} was not found"),
            Self::Repository(message) => write!(formatter, "identity repository failed: {message}"),
        }
    }
}

impl Error for IdentityError {}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use uuid::Version;

    use super::{
        ActorId, ActorKind, Identity, IdentityError, IdentityRepository, IdentityService,
        IdentityStatus, MAX_DISPLAY_NAME_LENGTH, REQUIREMENT,
    };

    #[derive(Default)]
    struct InMemoryIdentityRepository {
        identities: Mutex<HashMap<ActorId, Identity>>,
    }

    impl IdentityRepository for InMemoryIdentityRepository {
        fn insert(&self, identity: Identity) -> Result<(), IdentityError> {
            let mut identities = self.identities.lock().unwrap();
            if identities.contains_key(&identity.id()) {
                return Err(IdentityError::AlreadyExists(identity.id()));
            }
            identities.insert(identity.id(), identity);
            Ok(())
        }

        fn find(&self, id: ActorId) -> Result<Option<Identity>, IdentityError> {
            Ok(self.identities.lock().unwrap().get(&id).cloned())
        }

        fn save(&self, identity: Identity) -> Result<(), IdentityError> {
            let mut identities = self.identities.lock().unwrap();
            if !identities.contains_key(&identity.id()) {
                return Err(IdentityError::NotFound(identity.id()));
            }
            identities.insert(identity.id(), identity);
            Ok(())
        }
    }

    fn service() -> IdentityService<InMemoryIdentityRepository> {
        IdentityService::new(InMemoryIdentityRepository::default())
    }

    #[test]
    fn traces_to_identity_requirement() {
        assert_eq!(REQUIREMENT.id, "ILK-001");
        assert_eq!(REQUIREMENT.capability, "Identity");
    }

    #[test]
    fn generates_stable_random_actor_ids() {
        let id = ActorId::new();
        let serialized = id.to_string();

        assert_eq!(id.as_uuid().get_version(), Some(Version::Random));
        assert_eq!(serialized.parse::<ActorId>().unwrap(), id);
    }

    #[test]
    fn creates_each_required_service_kind_as_active() {
        let service = service();

        for kind in [ActorKind::Service, ActorKind::Worker] {
            let identity = service.create(kind, "Test actor").unwrap();
            assert_eq!(identity.kind(), kind);
            assert_eq!(identity.status(), IdentityStatus::Active);
        }
    }

    #[test]
    fn rejects_invalid_display_names_before_persistence() {
        let service = service();
        let too_long = "x".repeat(MAX_DISPLAY_NAME_LENGTH + 1);

        assert_eq!(
            service.create(ActorKind::Service, "   ").unwrap_err(),
            IdentityError::InvalidDisplayName
        );
        assert_eq!(
            service.create(ActorKind::Service, &too_long).unwrap_err(),
            IdentityError::InvalidDisplayName
        );
    }

    #[test]
    fn changing_metadata_does_not_change_the_stable_id() {
        let service = service();
        let original = service.create(ActorKind::Worker, "Worker one").unwrap();

        let renamed = service.rename(original.id(), "Worker renamed").unwrap();

        assert_eq!(renamed.id(), original.id());
        assert_eq!(renamed.display_name(), "Worker renamed");
    }

    #[test]
    fn disabled_identity_cannot_be_resolved_as_active() {
        let service = service();
        let identity = service.create(ActorKind::Service, "Indexer").unwrap();
        service.disable(identity.id()).unwrap();

        assert_eq!(
            service.resolve_active(identity.id()).unwrap_err(),
            IdentityError::Disabled(identity.id())
        );
    }

    #[test]
    fn unknown_identity_is_reported_explicitly() {
        let service = service();
        let id = ActorId::new();

        assert_eq!(
            service.resolve_active(id).unwrap_err(),
            IdentityError::NotFound(id)
        );
    }
}
