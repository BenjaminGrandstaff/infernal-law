//! Goal: independently verify the public minimum ILK-003 Request contract.

use infernal_law::kernel::identity::ActorId;
use infernal_law::kernel::requests::{ActionName, Request, RequestError, RequestId};
use uuid::Uuid;

#[test]
fn request_records_exactly_the_minimum_routing_identity() {
    let source = ActorId::new();
    let destination = ActorId::new();
    let request = Request::create(source, destination, "billing.invoice.submit").unwrap();

    assert_eq!(request.source_service(), source);
    assert_eq!(request.destination_service(), destination);
    assert_eq!(request.action().as_str(), "billing.invoice.submit");
    assert_ne!(*request.id().as_uuid(), Uuid::nil());
}

#[test]
fn stable_id_and_fields_can_be_restored_without_change() {
    let id = RequestId::new();
    let source = ActorId::new();
    let destination = ActorId::new();

    let restored = Request::restore(id, source, destination, "catalog.item.publish").unwrap();

    assert_eq!(restored.id(), id);
    assert_eq!(restored.source_service(), source);
    assert_eq!(restored.destination_service(), destination);
    assert_eq!(
        restored.action(),
        &ActionName::new("catalog.item.publish").unwrap()
    );
}

#[test]
fn separate_requests_receive_separate_ids() {
    let source = ActorId::new();
    let destination = ActorId::new();

    let first = Request::create(source, destination, "work.claim.create").unwrap();
    let second = Request::create(source, destination, "work.claim.create").unwrap();

    assert_ne!(first.id(), second.id());
}

#[test]
fn malformed_action_cannot_enter_the_request_contract() {
    let result = Request::create(ActorId::new(), ActorId::new(), "submit");

    assert_eq!(result, Err(RequestError::InvalidActionName));
}
