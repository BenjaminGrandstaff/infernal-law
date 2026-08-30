//! Goal: prove ILK-010 lifecycle and uniqueness rules independently from
//! PostgreSQL and transport concerns.

use std::sync::{Arc, Mutex};

use infernal_law::kernel::identity::ActorId;
use infernal_law::kernel::subscriptions::{
    DeliveryMode, EventType, Subscription, SubscriptionError, SubscriptionId,
    SubscriptionRepository, SubscriptionService,
};

#[derive(Clone, Default)]
struct MemorySubscriptions(Arc<Mutex<Vec<Subscription>>>);

impl SubscriptionRepository for MemorySubscriptions {
    fn insert(&self, subscription: Subscription) -> Result<(), SubscriptionError> {
        let mut values = self.0.lock().unwrap();
        if values.iter().any(|value| value.id() == subscription.id()) {
            return Err(SubscriptionError::AlreadyExists(subscription.id()));
        }
        if values.iter().any(|value| {
            value.service_id() == subscription.service_id()
                && value.event_type() == subscription.event_type()
                && value.is_active()
        }) {
            return Err(SubscriptionError::DuplicateActive(
                subscription.service_id(),
                subscription.event_type().clone(),
            ));
        }
        values.push(subscription);
        Ok(())
    }

    fn list_for_service(
        &self,
        service_id: ActorId,
    ) -> Result<Vec<Subscription>, SubscriptionError> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .iter()
            .filter(|value| value.service_id() == service_id)
            .cloned()
            .collect())
    }

    fn list_active_for_service(
        &self,
        service_id: ActorId,
    ) -> Result<Vec<Subscription>, SubscriptionError> {
        Ok(self
            .list_for_service(service_id)?
            .into_iter()
            .filter(Subscription::is_active)
            .collect())
    }

    fn disable(
        &self,
        service_id: ActorId,
        subscription_id: SubscriptionId,
        disabled_at: i64,
    ) -> Result<Subscription, SubscriptionError> {
        let mut values = self.0.lock().unwrap();
        let value = values
            .iter_mut()
            .find(|value| value.id() == subscription_id && value.service_id() == service_id)
            .ok_or(SubscriptionError::NotFound(subscription_id))?;
        if !value.is_active() {
            return Err(SubscriptionError::AlreadyDisabled(subscription_id));
        }
        let disabled = Subscription::restore(
            value.id(),
            value.service_id(),
            value.event_type().clone(),
            value.delivery_mode(),
            value.created_at(),
            Some(disabled_at),
        )?;
        *value = disabled.clone();
        Ok(disabled)
    }

    fn find_active_by_event_type(
        &self,
        event_type: &EventType,
    ) -> Result<Vec<Subscription>, SubscriptionError> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .iter()
            .filter(|value| value.event_type() == event_type && value.is_active())
            .cloned()
            .collect())
    }
}

#[test]
fn create_list_disable_and_resubscribe_preserve_history() {
    let service_id = ActorId::new();
    let subscriptions = SubscriptionService::new(MemorySubscriptions::default());
    let event_type = EventType::new("resource.version-created.v1").unwrap();

    let first = subscriptions
        .create(service_id, event_type.clone(), DeliveryMode::Inclusive, 10)
        .unwrap();
    assert!(matches!(
        subscriptions.create(service_id, event_type.clone(), DeliveryMode::Inclusive, 11),
        Err(SubscriptionError::DuplicateActive(id, event))
            if id == service_id && event == event_type
    ));
    let disabled = subscriptions.disable(service_id, first.id(), 20).unwrap();
    assert_eq!(disabled.disabled_at(), Some(20));
    assert!(subscriptions.list_active(service_id).unwrap().is_empty());

    let second = subscriptions
        .create(service_id, event_type.clone(), DeliveryMode::Inclusive, 30)
        .unwrap();
    assert_ne!(second.id(), first.id());
    let history = subscriptions.list(service_id).unwrap();
    assert_eq!(history.len(), 2);
    assert_eq!(history.iter().filter(|value| value.is_active()).count(), 1);
    assert_eq!(history[0].id(), first.id());
    assert_eq!(history[1].id(), second.id());
}

#[test]
fn service_ownership_and_disable_state_are_enforced() {
    let owner = ActorId::new();
    let other_service = ActorId::new();
    let subscriptions = SubscriptionService::new(MemorySubscriptions::default());
    let created = subscriptions
        .create(
            owner,
            EventType::new("artifact.submitted.v1").unwrap(),
            DeliveryMode::Inclusive,
            10,
        )
        .unwrap();

    assert_eq!(
        subscriptions.disable(other_service, created.id(), 11),
        Err(SubscriptionError::NotFound(created.id()))
    );
    subscriptions.disable(owner, created.id(), 12).unwrap();
    assert_eq!(
        subscriptions.disable(owner, created.id(), 13),
        Err(SubscriptionError::AlreadyDisabled(created.id()))
    );
}

#[test]
fn invalid_timestamps_fail_before_persistence() {
    let repository = MemorySubscriptions::default();
    let subscriptions = SubscriptionService::new(repository.clone());
    assert_eq!(
        subscriptions.create(
            ActorId::new(),
            EventType::new("event.created.v1").unwrap(),
            DeliveryMode::Inclusive,
            -1,
        ),
        Err(SubscriptionError::InvalidTimestamp)
    );
    assert!(repository.0.lock().unwrap().is_empty());
}

#[test]
fn find_active_by_event_type_matches_across_services_and_excludes_disabled() {
    let subscriptions = SubscriptionService::new(MemorySubscriptions::default());
    let event_type = EventType::new("billing.invoice.submit").unwrap();
    let first_service = ActorId::new();
    let second_service = ActorId::new();

    let first = subscriptions
        .create(
            first_service,
            event_type.clone(),
            DeliveryMode::Inclusive,
            10,
        )
        .unwrap();
    subscriptions
        .create(
            second_service,
            event_type.clone(),
            DeliveryMode::Inclusive,
            11,
        )
        .unwrap();
    subscriptions
        .create(
            ActorId::new(),
            EventType::new("billing.invoice.cancel").unwrap(),
            DeliveryMode::Inclusive,
            12,
        )
        .unwrap();
    subscriptions
        .disable(first_service, first.id(), 20)
        .unwrap();

    let matches = subscriptions
        .find_active_by_event_type(&event_type)
        .unwrap();

    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].service_id(), second_service);
}
