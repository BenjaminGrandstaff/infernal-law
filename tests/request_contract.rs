//! Goal: independently verify the public minimum ILK-003 Request contract.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::thread;

use infernal_law::kernel::identity::ActorId;
use infernal_law::kernel::requests::{
    AcceptedRequest, ActionName, Request, RequestAcceptance, RequestError, RequestFingerprint,
    RequestId, RequestRepository, RequestService,
};
use uuid::Uuid;

#[derive(Default)]
struct RequestState {
    records: HashMap<(ActorId, RequestId), AcceptedRequest>,
    next_accepted_at: i64,
}

#[derive(Clone, Default)]
struct MemoryRequests(Arc<Mutex<RequestState>>);

impl RequestRepository for MemoryRequests {
    fn accept(
        &self,
        request: Request,
        fingerprint: RequestFingerprint,
    ) -> Result<RequestAcceptance, RequestError> {
        let mut state = self.0.lock().unwrap();
        let key = (request.source_service(), request.id());
        if let Some(stored) = state.records.get(&key) {
            return if stored.request() == &request && stored.fingerprint() == fingerprint {
                Ok(RequestAcceptance::SafeRetry(stored.clone()))
            } else {
                Err(RequestError::RequestIdConflict(request.id()))
            };
        }

        let accepted_at = state.next_accepted_at;
        state.next_accepted_at += 1;
        let record = AcceptedRequest::restore(request, fingerprint, accepted_at)?;
        state.records.insert(key, record.clone());
        Ok(RequestAcceptance::Accepted(record))
    }

    fn find(
        &self,
        source_service: ActorId,
        request_id: RequestId,
    ) -> Result<Option<AcceptedRequest>, RequestError> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .records
            .get(&(source_service, request_id))
            .cloned())
    }
}

fn fingerprint(byte: u8) -> RequestFingerprint {
    RequestFingerprint::from_bytes([byte; 32])
}

#[test]
fn request_creation_requires_no_destination_discovery_or_subscription() {
    let source = ActorId::new();
    let request = Request::create(source, "billing.invoice.submit").unwrap();

    assert_eq!(request.source_service(), source);
    assert_eq!(request.action().as_str(), "billing.invoice.submit");
    assert_ne!(*request.id().as_uuid(), Uuid::nil());
}

#[test]
fn stable_id_and_fields_can_be_restored_without_change() {
    let id = RequestId::new();
    let source = ActorId::new();

    let restored = Request::restore(id, source, "catalog.item.publish").unwrap();

    assert_eq!(restored.id(), id);
    assert_eq!(restored.source_service(), source);
    assert_eq!(
        restored.action(),
        &ActionName::new("catalog.item.publish").unwrap()
    );
}

#[test]
fn separate_requests_receive_separate_ids() {
    let source = ActorId::new();

    let first = Request::create(source, "work.claim.create").unwrap();
    let second = Request::create(source, "work.claim.create").unwrap();

    assert_ne!(first.id(), second.id());
}

#[test]
fn malformed_action_cannot_enter_the_request_contract() {
    let result = Request::create(ActorId::new(), "submit");

    assert_eq!(result, Err(RequestError::InvalidActionName));
}

#[test]
fn acceptance_is_durable_through_the_repository_contract_and_safe_to_retry() {
    let requests = RequestService::new(MemoryRequests::default());
    let request = Request::create(ActorId::new(), "billing.invoice.submit").unwrap();

    let accepted = requests.accept(request.clone(), fingerprint(1)).unwrap();
    assert!(accepted.is_fresh());
    let retry = requests.accept(request.clone(), fingerprint(1)).unwrap();
    assert!(matches!(retry, RequestAcceptance::SafeRetry(_)));
    assert_eq!(retry.record(), accepted.record());
    assert_eq!(
        requests
            .find(request.source_service(), request.id())
            .unwrap(),
        Some(accepted.record().clone())
    );
}

#[test]
fn request_id_cannot_be_rebound_to_another_action_or_fingerprint() {
    let requests = RequestService::new(MemoryRequests::default());
    let source = ActorId::new();
    let id = RequestId::new();
    let original = Request::restore(id, source, "billing.invoice.submit").unwrap();
    requests.accept(original.clone(), fingerprint(2)).unwrap();

    assert_eq!(
        requests.accept(original, fingerprint(3)),
        Err(RequestError::RequestIdConflict(id))
    );
    assert_eq!(
        requests.accept(
            Request::restore(id, source, "billing.invoice.cancel").unwrap(),
            fingerprint(2),
        ),
        Err(RequestError::RequestIdConflict(id))
    );
}

#[test]
fn request_ids_are_scoped_to_the_authenticated_source() {
    let requests = RequestService::new(MemoryRequests::default());
    let id = RequestId::new();
    let first = Request::restore(id, ActorId::new(), "work.item.submit").unwrap();
    let second = Request::restore(id, ActorId::new(), "work.item.submit").unwrap();

    assert!(requests.accept(first, fingerprint(4)).unwrap().is_fresh());
    assert!(requests.accept(second, fingerprint(4)).unwrap().is_fresh());
}

#[test]
fn concurrent_acceptance_has_one_fresh_result_and_no_duplicate_record() {
    let repository = MemoryRequests::default();
    let requests = RequestService::new(repository.clone());
    let request = Request::create(ActorId::new(), "work.item.submit").unwrap();
    let outcomes: Vec<_> = (0..16)
        .map(|_| {
            let requests = requests.clone();
            let request = request.clone();
            thread::spawn(move || requests.accept(request, fingerprint(5)).unwrap())
        })
        .map(|handle| handle.join().unwrap())
        .collect();

    assert_eq!(outcomes.iter().filter(|value| value.is_fresh()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|value| matches!(value, RequestAcceptance::SafeRetry(_)))
            .count(),
        15
    );
    assert_eq!(repository.0.lock().unwrap().records.len(), 1);
}
