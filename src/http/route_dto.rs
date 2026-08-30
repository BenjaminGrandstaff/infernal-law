//! Goal: define the eligible-route JSON wire format an external scheduler
//! queries (ADR-0011), kept separate from HTTP status/error-code mapping
//! (`src/http.rs`) the same way `subscription_dto` and `work_claim_dto`
//! separate their wire shapes from dispatch.

use serde::Serialize;

use crate::kernel::requests::Route;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RouteResponse {
    pub route_id: String,
    pub request_id: String,
    pub subscription_id: String,
    pub destination_service_id: String,
    pub created_at: i64,
}

impl From<&Route> for RouteResponse {
    fn from(route: &Route) -> Self {
        Self {
            route_id: route.id().to_string(),
            request_id: route.request_id().to_string(),
            subscription_id: route.subscription_id().to_string(),
            destination_service_id: route.destination_service().to_string(),
            created_at: route.created_at(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EligibleRouteListResponse {
    pub routes: Vec<RouteResponse>,
}

impl FromIterator<RouteResponse> for EligibleRouteListResponse {
    fn from_iter<I: IntoIterator<Item = RouteResponse>>(iter: I) -> Self {
        Self {
            routes: iter.into_iter().collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::identity::ActorId;
    use crate::kernel::requests::RequestId;
    use crate::kernel::subscriptions::SubscriptionId;

    #[test]
    fn converts_a_route_into_its_wire_format() {
        let destination = ActorId::new();
        let route = Route::create(
            ActorId::new(),
            RequestId::new(),
            SubscriptionId::new(),
            destination,
            100,
        )
        .unwrap();

        let response = RouteResponse::from(&route);

        assert_eq!(response.route_id, route.id().to_string());
        assert_eq!(response.destination_service_id, destination.to_string());
        assert_eq!(response.created_at, 100);
    }

    #[test]
    fn collects_routes_into_a_list_response() {
        let route = Route::create(
            ActorId::new(),
            RequestId::new(),
            SubscriptionId::new(),
            ActorId::new(),
            5,
        )
        .unwrap();

        let response: EligibleRouteListResponse =
            [&route].into_iter().map(RouteResponse::from).collect();

        assert_eq!(response.routes.len(), 1);
    }
}
