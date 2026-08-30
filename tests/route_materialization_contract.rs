//! Goal: independently verify the ILK-003 route-materialization contract --
//! idempotent materialization keyed by (request_id, subscription_id), and
//! that one request can have independent routes to many destinations.

use std::sync::{Arc, Mutex};

use infernal_law::kernel::identity::ActorId;
use infernal_law::kernel::requests::{
    RequestError, RequestId, Route, RouteRepository, RouteService,
};
use infernal_law::kernel::subscriptions::SubscriptionId;

#[derive(Clone, Default)]
struct MemoryRoutes(Arc<Mutex<Vec<Route>>>);

impl RouteRepository for MemoryRoutes {
    fn materialize(&self, route: Route) -> Result<Route, RequestError> {
        let mut routes = self.0.lock().unwrap();
        if let Some(existing) = routes.iter().find(|value| {
            value.request_id() == route.request_id()
                && value.subscription_id() == route.subscription_id()
        }) {
            return Ok(existing.clone());
        }
        routes.push(route.clone());
        Ok(route)
    }

    fn list_for_request(&self, request_id: RequestId) -> Result<Vec<Route>, RequestError> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .iter()
            .filter(|route| route.request_id() == request_id)
            .cloned()
            .collect())
    }
}

#[test]
fn materializing_the_same_match_twice_returns_the_same_route() {
    let routes = RouteService::new(MemoryRoutes::default());
    let source = ActorId::new();
    let request_id = RequestId::new();
    let subscription_id = SubscriptionId::new();
    let destination = ActorId::new();

    let first = routes
        .materialize(source, request_id, subscription_id, destination, 10)
        .unwrap();
    let second = routes
        .materialize(source, request_id, subscription_id, destination, 20)
        .unwrap();

    assert_eq!(first.id(), second.id());
    assert_eq!(first.created_at(), 10, "the first materialization wins");
    assert_eq!(routes.list_for_request(request_id).unwrap().len(), 1);
}

#[test]
fn one_request_can_have_independent_routes_to_many_destinations() {
    let routes = RouteService::new(MemoryRoutes::default());
    let source = ActorId::new();
    let request_id = RequestId::new();
    let first_subscription = SubscriptionId::new();
    let second_subscription = SubscriptionId::new();

    let first_route = routes
        .materialize(source, request_id, first_subscription, ActorId::new(), 10)
        .unwrap();
    let second_route = routes
        .materialize(source, request_id, second_subscription, ActorId::new(), 10)
        .unwrap();

    assert_ne!(first_route.id(), second_route.id());
    let all = routes.list_for_request(request_id).unwrap();
    assert_eq!(all.len(), 2);
}

#[test]
fn routes_to_different_requests_never_collide() {
    let routes = RouteService::new(MemoryRoutes::default());
    let source = ActorId::new();
    let subscription_id = SubscriptionId::new();
    let destination = ActorId::new();

    let first_request = RequestId::new();
    let second_request = RequestId::new();
    routes
        .materialize(source, first_request, subscription_id, destination, 10)
        .unwrap();
    routes
        .materialize(source, second_request, subscription_id, destination, 10)
        .unwrap();

    assert_eq!(routes.list_for_request(first_request).unwrap().len(), 1);
    assert_eq!(routes.list_for_request(second_request).unwrap().len(), 1);
}
