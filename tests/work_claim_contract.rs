//! Goal: independently verify the ILK-011 work-claim contract -- exactly
//! one current holder per route, atomic claim/renew/release/complete, and
//! that a fenced-out holder can never renew or complete after losing its
//! claim.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::thread;

use infernal_law::kernel::identity::ActorId;
use infernal_law::kernel::instance_keys::InstanceId;
use infernal_law::kernel::requests::RouteId;
use infernal_law::kernel::work_claims::{
    ClaimId, WorkClaim, WorkClaimError, WorkClaimRepository, WorkClaimService, WorkClaimStatus,
};

#[derive(Clone, Default)]
struct MemoryWorkClaims {
    route_destinations: Arc<Mutex<HashMap<RouteId, ActorId>>>,
    claims: Arc<Mutex<Vec<WorkClaim>>>,
}

impl MemoryWorkClaims {
    fn with_route(route_id: RouteId, destination: ActorId) -> Self {
        let repository = Self::default();
        repository
            .route_destinations
            .lock()
            .unwrap()
            .insert(route_id, destination);
        repository
    }
}

impl WorkClaimRepository for MemoryWorkClaims {
    fn claim(
        &self,
        route_id: RouteId,
        worker_service: ActorId,
        worker_instance: InstanceId,
        lease_expires_at: i64,
        now: i64,
    ) -> Result<WorkClaim, WorkClaimError> {
        let destinations = self.route_destinations.lock().unwrap();
        if destinations.get(&route_id) != Some(&worker_service) {
            return Err(WorkClaimError::RouteNotFound(route_id));
        }
        let mut claims = self.claims.lock().unwrap();
        let latest = claims
            .iter_mut()
            .filter(|claim| claim.route_id() == route_id)
            .max_by_key(|claim| claim.fencing_token());
        let next_fencing_token = match latest {
            Some(claim) if claim.is_current(now) => {
                return Err(WorkClaimError::AlreadyClaimed(route_id));
            }
            Some(claim) => {
                let fencing_token = claim.fencing_token();
                if matches!(claim.status(), WorkClaimStatus::Active) {
                    *claim = WorkClaim::restore(
                        claim.id(),
                        claim.route_id(),
                        claim.worker_service(),
                        claim.worker_instance(),
                        claim.fencing_token(),
                        WorkClaimStatus::Expired,
                        claim.claimed_at(),
                        claim.lease_expires_at(),
                    )
                    .unwrap();
                }
                fencing_token + 1
            }
            None => 1,
        };
        let claim = WorkClaim::restore(
            ClaimId::new(),
            route_id,
            worker_service,
            worker_instance,
            next_fencing_token,
            WorkClaimStatus::Active,
            now,
            lease_expires_at,
        )
        .unwrap();
        claims.push(claim.clone());
        Ok(claim)
    }

    fn renew(
        &self,
        claim_id: ClaimId,
        fencing_token: i64,
        lease_expires_at: i64,
        now: i64,
    ) -> Result<WorkClaim, WorkClaimError> {
        let mut claims = self.claims.lock().unwrap();
        let claim = current_claim(&mut claims, claim_id, fencing_token, now)?;
        *claim = WorkClaim::restore(
            claim.id(),
            claim.route_id(),
            claim.worker_service(),
            claim.worker_instance(),
            claim.fencing_token(),
            WorkClaimStatus::Active,
            claim.claimed_at(),
            lease_expires_at,
        )
        .unwrap();
        Ok(claim.clone())
    }

    fn release(
        &self,
        claim_id: ClaimId,
        fencing_token: i64,
        now: i64,
    ) -> Result<WorkClaim, WorkClaimError> {
        transition(
            &self.claims,
            claim_id,
            fencing_token,
            now,
            WorkClaimStatus::Released,
        )
    }

    fn complete(
        &self,
        claim_id: ClaimId,
        fencing_token: i64,
        now: i64,
    ) -> Result<WorkClaim, WorkClaimError> {
        transition(
            &self.claims,
            claim_id,
            fencing_token,
            now,
            WorkClaimStatus::Completed,
        )
    }

    fn find(&self, claim_id: ClaimId) -> Result<Option<WorkClaim>, WorkClaimError> {
        Ok(self
            .claims
            .lock()
            .unwrap()
            .iter()
            .find(|claim| claim.id() == claim_id)
            .cloned())
    }
}

fn current_claim(
    claims: &mut [WorkClaim],
    claim_id: ClaimId,
    fencing_token: i64,
    now: i64,
) -> Result<&mut WorkClaim, WorkClaimError> {
    let claim = claims
        .iter_mut()
        .find(|claim| claim.id() == claim_id)
        .ok_or(WorkClaimError::NotFound(claim_id))?;
    if claim.fencing_token() != fencing_token || !claim.is_current(now) {
        return Err(WorkClaimError::Fenced);
    }
    Ok(claim)
}

fn transition(
    claims: &Arc<Mutex<Vec<WorkClaim>>>,
    claim_id: ClaimId,
    fencing_token: i64,
    now: i64,
    status: WorkClaimStatus,
) -> Result<WorkClaim, WorkClaimError> {
    let mut claims = claims.lock().unwrap();
    let claim = current_claim(&mut claims, claim_id, fencing_token, now)?;
    *claim = WorkClaim::restore(
        claim.id(),
        claim.route_id(),
        claim.worker_service(),
        claim.worker_instance(),
        claim.fencing_token(),
        status,
        claim.claimed_at(),
        claim.lease_expires_at(),
    )
    .unwrap();
    Ok(claim.clone())
}

#[test]
fn claiming_an_unowned_or_unknown_route_is_rejected() {
    let worker = ActorId::new();
    let route_id = RouteId::new();
    let repository = MemoryWorkClaims::with_route(route_id, ActorId::new());
    let claims = WorkClaimService::new(repository);

    assert_eq!(
        claims.claim(route_id, worker, InstanceId::new(), 100, 0),
        Err(WorkClaimError::RouteNotFound(route_id))
    );
}

#[test]
fn a_second_claim_attempt_is_rejected_while_the_first_is_current() {
    let destination = ActorId::new();
    let route_id = RouteId::new();
    let repository = MemoryWorkClaims::with_route(route_id, destination);
    let claims = WorkClaimService::new(repository);
    claims
        .claim(route_id, destination, InstanceId::new(), 100, 0)
        .unwrap();

    assert_eq!(
        claims.claim(route_id, destination, InstanceId::new(), 100, 1),
        Err(WorkClaimError::AlreadyClaimed(route_id))
    );
}

#[test]
fn another_worker_can_claim_after_the_prior_lease_expires() {
    let destination = ActorId::new();
    let route_id = RouteId::new();
    let repository = MemoryWorkClaims::with_route(route_id, destination);
    let claims = WorkClaimService::new(repository);
    let first = claims
        .claim(route_id, destination, InstanceId::new(), 50, 0)
        .unwrap();

    let second = claims
        .claim(route_id, destination, InstanceId::new(), 150, 60)
        .unwrap();

    assert_eq!(second.fencing_token(), first.fencing_token() + 1);
    assert!(!claims.find(first.id()).unwrap().unwrap().is_current(60));
}

#[test]
fn a_stale_holder_cannot_renew_release_or_complete_after_losing_its_claim() {
    let destination = ActorId::new();
    let route_id = RouteId::new();
    let repository = MemoryWorkClaims::with_route(route_id, destination);
    let claims = WorkClaimService::new(repository);
    let first = claims
        .claim(route_id, destination, InstanceId::new(), 50, 0)
        .unwrap();
    claims
        .claim(route_id, destination, InstanceId::new(), 150, 60)
        .unwrap();

    assert_eq!(
        claims.renew(first.id(), first.fencing_token(), 200, 61),
        Err(WorkClaimError::Fenced)
    );
    assert_eq!(
        claims.release(first.id(), first.fencing_token(), 61),
        Err(WorkClaimError::Fenced)
    );
    assert_eq!(
        claims.complete(first.id(), first.fencing_token(), 61),
        Err(WorkClaimError::Fenced)
    );
}

#[test]
fn the_current_holder_can_renew_extending_the_lease_without_changing_the_fencing_token() {
    let destination = ActorId::new();
    let route_id = RouteId::new();
    let repository = MemoryWorkClaims::with_route(route_id, destination);
    let claims = WorkClaimService::new(repository);
    let claim = claims
        .claim(route_id, destination, InstanceId::new(), 50, 0)
        .unwrap();

    let renewed = claims
        .renew(claim.id(), claim.fencing_token(), 500, 10)
        .unwrap();

    assert_eq!(renewed.fencing_token(), claim.fencing_token());
    assert_eq!(renewed.lease_expires_at(), 500);
    assert!(renewed.is_current(400));
}

#[test]
fn releasing_a_claim_allows_immediate_reclaim_without_waiting_for_expiry() {
    let destination = ActorId::new();
    let route_id = RouteId::new();
    let repository = MemoryWorkClaims::with_route(route_id, destination);
    let claims = WorkClaimService::new(repository);
    let claim = claims
        .claim(route_id, destination, InstanceId::new(), 1_000, 0)
        .unwrap();
    claims
        .release(claim.id(), claim.fencing_token(), 5)
        .unwrap();

    let second = claims
        .claim(route_id, destination, InstanceId::new(), 1_000, 5)
        .unwrap();

    assert_eq!(second.fencing_token(), claim.fencing_token() + 1);
}

#[test]
fn completion_is_terminal_and_cannot_be_renewed_or_released_afterward() {
    let destination = ActorId::new();
    let route_id = RouteId::new();
    let repository = MemoryWorkClaims::with_route(route_id, destination);
    let claims = WorkClaimService::new(repository);
    let claim = claims
        .claim(route_id, destination, InstanceId::new(), 1_000, 0)
        .unwrap();
    let completed = claims
        .complete(claim.id(), claim.fencing_token(), 5)
        .unwrap();
    assert!(matches!(completed.status(), WorkClaimStatus::Completed));

    assert_eq!(
        claims.renew(claim.id(), claim.fencing_token(), 2_000, 6),
        Err(WorkClaimError::Fenced)
    );
    assert_eq!(
        claims.release(claim.id(), claim.fencing_token(), 6),
        Err(WorkClaimError::Fenced)
    );
}

#[test]
fn concurrent_claim_attempts_on_the_same_route_produce_exactly_one_active_holder() {
    let destination = ActorId::new();
    let route_id = RouteId::new();
    let repository = MemoryWorkClaims::with_route(route_id, destination);
    let claims = WorkClaimService::new(repository);
    let outcomes: Vec<_> = (0..16)
        .map(|_| {
            let claims = claims.clone();
            thread::spawn(move || claims.claim(route_id, destination, InstanceId::new(), 1_000, 0))
        })
        .map(|handle| handle.join().unwrap())
        .collect();

    assert_eq!(outcomes.iter().filter(|value| value.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|value| matches!(value, Err(WorkClaimError::AlreadyClaimed(_))))
            .count(),
        15
    );
}
