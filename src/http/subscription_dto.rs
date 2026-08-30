//! Goal: define the ILK-010 subscription JSON wire format, kept separate
//! from HTTP status/error-code mapping (`src/http.rs`) the same way
//! `enrollment_dto` separates enrollment's wire shapes from its dispatch.

use serde::{Deserialize, Serialize};

use crate::kernel::subscriptions::{EventType, Subscription, SubscriptionError};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateSubscriptionRequest {
    event_type: String,
}

impl CreateSubscriptionRequest {
    pub fn event_type(&self) -> Result<EventType, SubscriptionError> {
        EventType::new(&self.event_type)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SubscriptionResponse {
    pub id: String,
    pub service_id: String,
    pub event_type: String,
    pub created_at: i64,
    pub disabled_at: Option<i64>,
    pub active: bool,
}

impl From<&Subscription> for SubscriptionResponse {
    fn from(subscription: &Subscription) -> Self {
        Self {
            id: subscription.id().to_string(),
            service_id: subscription.service_id().to_string(),
            event_type: subscription.event_type().as_str().to_owned(),
            created_at: subscription.created_at(),
            disabled_at: subscription.disabled_at(),
            active: subscription.is_active(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SubscriptionListResponse {
    pub subscriptions: Vec<SubscriptionResponse>,
}

impl FromIterator<SubscriptionResponse> for SubscriptionListResponse {
    fn from_iter<I: IntoIterator<Item = SubscriptionResponse>>(iter: I) -> Self {
        Self {
            subscriptions: iter.into_iter().collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::identity::ActorId;

    #[test]
    fn rejects_unknown_fields_in_the_create_request() {
        let result: Result<CreateSubscriptionRequest, _> =
            serde_json::from_str(r#"{"event_type":"a.b.c","extra":true}"#);
        assert!(result.is_err());
    }

    #[test]
    fn event_type_validation_is_delegated_to_the_domain_type() {
        let dto: CreateSubscriptionRequest =
            serde_json::from_str(r#"{"event_type":"Not Valid"}"#).unwrap();
        assert_eq!(dto.event_type(), Err(SubscriptionError::InvalidEventType));
    }

    #[test]
    fn response_reflects_active_and_disabled_state() {
        let subscription = Subscription::restore(
            crate::kernel::subscriptions::SubscriptionId::new(),
            ActorId::new(),
            EventType::new("resource.created.v1").unwrap(),
            crate::kernel::subscriptions::DeliveryMode::Inclusive,
            10,
            None,
        )
        .unwrap();
        let response = SubscriptionResponse::from(&subscription);
        assert!(response.active);
        assert_eq!(response.disabled_at, None);
    }
}
