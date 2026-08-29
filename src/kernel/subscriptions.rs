//! Goal: implement ILK-010 with durable, typed event interests owned by stable
//! service identities while preserving disabled subscription history.

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

use uuid::Uuid;

use super::Requirement;
use super::identity::ActorId;

pub const REQUIREMENT: Requirement = Requirement::new(
    "ILK-010",
    "Subscriptions",
    "Workers can declare the event types in which they are interested.",
);

pub const MAX_EVENT_TYPE_LENGTH: usize = 200;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SubscriptionId(Uuid);

impl SubscriptionId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    pub const fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

impl Default for SubscriptionId {
    fn default() -> Self {
        Self::new()
    }
}

impl Display for SubscriptionId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.0, formatter)
    }
}

impl FromStr for SubscriptionId {
    type Err = SubscriptionError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(value)
            .map(Self)
            .map_err(|_| SubscriptionError::InvalidSubscriptionId)
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct EventType(String);

impl EventType {
    pub fn new(value: &str) -> Result<Self, SubscriptionError> {
        let value = value.trim();
        if value.is_empty()
            || value.chars().count() > MAX_EVENT_TYPE_LENGTH
            || !value.split('.').all(valid_event_segment)
        {
            return Err(SubscriptionError::InvalidEventType);
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for EventType {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for EventType {
    type Err = SubscriptionError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

fn valid_event_segment(segment: &str) -> bool {
    let mut characters = segment.chars();
    characters
        .next()
        .is_some_and(|character| character.is_ascii_lowercase())
        && characters.all(|character| {
            character.is_ascii_lowercase()
                || character.is_ascii_digit()
                || character == '-'
                || character == '_'
        })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Subscription {
    id: SubscriptionId,
    service_id: ActorId,
    event_type: EventType,
    created_at: i64,
    disabled_at: Option<i64>,
}

impl Subscription {
    fn create(
        service_id: ActorId,
        event_type: EventType,
        now: i64,
    ) -> Result<Self, SubscriptionError> {
        Self::restore(SubscriptionId::new(), service_id, event_type, now, None)
    }

    pub fn restore(
        id: SubscriptionId,
        service_id: ActorId,
        event_type: EventType,
        created_at: i64,
        disabled_at: Option<i64>,
    ) -> Result<Self, SubscriptionError> {
        if created_at < 0 || disabled_at.is_some_and(|value| value < created_at) {
            return Err(SubscriptionError::InvalidTimestamp);
        }
        Ok(Self {
            id,
            service_id,
            event_type,
            created_at,
            disabled_at,
        })
    }

    pub const fn id(&self) -> SubscriptionId {
        self.id
    }

    pub const fn service_id(&self) -> ActorId {
        self.service_id
    }

    pub const fn event_type(&self) -> &EventType {
        &self.event_type
    }

    pub const fn created_at(&self) -> i64 {
        self.created_at
    }

    pub const fn disabled_at(&self) -> Option<i64> {
        self.disabled_at
    }

    pub const fn is_active(&self) -> bool {
        self.disabled_at.is_none()
    }
}

pub trait SubscriptionRepository: Send + Sync {
    fn insert(&self, subscription: Subscription) -> Result<(), SubscriptionError>;
    fn list_for_service(&self, service_id: ActorId)
    -> Result<Vec<Subscription>, SubscriptionError>;
    fn list_active_for_service(
        &self,
        service_id: ActorId,
    ) -> Result<Vec<Subscription>, SubscriptionError>;
    fn disable(
        &self,
        service_id: ActorId,
        subscription_id: SubscriptionId,
        disabled_at: i64,
    ) -> Result<Subscription, SubscriptionError>;
}

#[derive(Clone)]
pub struct SubscriptionService<R> {
    repository: R,
}

impl<R> SubscriptionService<R>
where
    R: SubscriptionRepository,
{
    pub const fn new(repository: R) -> Self {
        Self { repository }
    }

    pub fn create(
        &self,
        service_id: ActorId,
        event_type: EventType,
        now: i64,
    ) -> Result<Subscription, SubscriptionError> {
        let subscription = Subscription::create(service_id, event_type, now)?;
        self.repository.insert(subscription.clone())?;
        Ok(subscription)
    }

    pub fn list(&self, service_id: ActorId) -> Result<Vec<Subscription>, SubscriptionError> {
        self.repository.list_for_service(service_id)
    }

    pub fn list_active(&self, service_id: ActorId) -> Result<Vec<Subscription>, SubscriptionError> {
        self.repository.list_active_for_service(service_id)
    }

    pub fn disable(
        &self,
        service_id: ActorId,
        subscription_id: SubscriptionId,
        now: i64,
    ) -> Result<Subscription, SubscriptionError> {
        if now < 0 {
            return Err(SubscriptionError::InvalidTimestamp);
        }
        self.repository.disable(service_id, subscription_id, now)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SubscriptionError {
    AlreadyExists(SubscriptionId),
    AlreadyDisabled(SubscriptionId),
    DuplicateActive(ActorId, EventType),
    InvalidEventType,
    InvalidSubscriptionId,
    InvalidTimestamp,
    NotFound(SubscriptionId),
    Repository(String),
    UnknownService(ActorId),
}

impl Display for SubscriptionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyExists(id) => write!(formatter, "subscription {id} already exists"),
            Self::AlreadyDisabled(id) => write!(formatter, "subscription {id} is already disabled"),
            Self::DuplicateActive(service_id, event_type) => write!(
                formatter,
                "service {service_id} already has an active subscription for {event_type}"
            ),
            Self::InvalidEventType => {
                formatter.write_str("event type must contain lowercase dot-separated name segments")
            }
            Self::InvalidSubscriptionId => {
                formatter.write_str("subscription ID must be a valid UUID")
            }
            Self::InvalidTimestamp => formatter.write_str("subscription timestamp is invalid"),
            Self::NotFound(id) => write!(formatter, "subscription {id} was not found"),
            Self::Repository(message) => {
                write!(formatter, "subscription repository failed: {message}")
            }
            Self::UnknownService(id) => write!(formatter, "service identity {id} was not found"),
        }
    }
}

impl Error for SubscriptionError {}

#[cfg(test)]
mod tests {
    use super::{EventType, REQUIREMENT, SubscriptionError, SubscriptionId};

    #[test]
    fn traces_to_subscriptions_requirement() {
        assert_eq!(REQUIREMENT.id, "ILK-010");
        assert_eq!(REQUIREMENT.capability, "Subscriptions");
    }

    #[test]
    fn event_types_are_typed_and_canonical() {
        assert_eq!(
            EventType::new("resource.version-created.v1")
                .unwrap()
                .as_str(),
            "resource.version-created.v1"
        );
        for invalid in [
            "",
            "Resource.Created",
            ".resource",
            "resource..created",
            "resource created",
        ] {
            assert_eq!(
                EventType::new(invalid),
                Err(SubscriptionError::InvalidEventType)
            );
        }
    }

    #[test]
    fn subscription_ids_round_trip_as_uuids() {
        let id = SubscriptionId::new();
        assert_eq!(id.to_string().parse::<SubscriptionId>().unwrap(), id);
    }
}
