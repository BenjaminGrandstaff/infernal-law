//! Goal: implement ILK-011 by ensuring only one worker holds an active claim
//! for a route at a time, atomically, with a monotonically increasing
//! fencing token so a stale holder can never complete or renew after losing
//! its claim.

use std::collections::HashSet;
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

use uuid::Uuid;

use super::Requirement;
use super::identity::ActorId;
use super::instance_keys::InstanceId;
use super::requests::RouteId;

pub const REQUIREMENT: Requirement = Requirement::new(
    "ILK-011",
    "Work claims",
    "At most one worker can hold the active claim for a piece of work.",
);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ClaimId(Uuid);

impl ClaimId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    pub const fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

impl Default for ClaimId {
    fn default() -> Self {
        Self::new()
    }
}

impl Display for ClaimId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.0, formatter)
    }
}

impl FromStr for ClaimId {
    type Err = WorkClaimError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(value)
            .map(Self)
            .map_err(|_| WorkClaimError::InvalidClaimId)
    }
}

/// A claim's outcome, once it leaves `Active`. Terminal once set --
/// mirrors how `authority_schema_versions` protects its own status column,
/// so append-only history exists at the storage layer, not merely by
/// convention in Rust.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkClaimStatus {
    Active,
    Completed,
    Released,
    Expired,
}

/// One worker's hold on a route, bound to the exact worker instance,
/// lease window, and fencing token that authorize it. A new claim on the
/// same route always carries `fencing_token` one higher than whatever it
/// superseded (an expired or released prior claim); presenting a fencing
/// token that is not the current one is indistinguishable from presenting
/// none at all -- both mean the caller has already lost the claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkClaim {
    id: ClaimId,
    route_id: RouteId,
    worker_service: ActorId,
    worker_instance: InstanceId,
    fencing_token: i64,
    status: WorkClaimStatus,
    claimed_at: i64,
    lease_expires_at: i64,
}

impl WorkClaim {
    #[allow(clippy::too_many_arguments)]
    pub fn restore(
        id: ClaimId,
        route_id: RouteId,
        worker_service: ActorId,
        worker_instance: InstanceId,
        fencing_token: i64,
        status: WorkClaimStatus,
        claimed_at: i64,
        lease_expires_at: i64,
    ) -> Result<Self, WorkClaimError> {
        if fencing_token < 1 {
            return Err(WorkClaimError::InvalidFencingToken);
        }
        if claimed_at < 0 || lease_expires_at <= claimed_at {
            return Err(WorkClaimError::InvalidLease);
        }
        Ok(Self {
            id,
            route_id,
            worker_service,
            worker_instance,
            fencing_token,
            status,
            claimed_at,
            lease_expires_at,
        })
    }

    pub const fn id(&self) -> ClaimId {
        self.id
    }

    pub const fn route_id(&self) -> RouteId {
        self.route_id
    }

    pub const fn worker_service(&self) -> ActorId {
        self.worker_service
    }

    pub const fn worker_instance(&self) -> InstanceId {
        self.worker_instance
    }

    pub const fn fencing_token(&self) -> i64 {
        self.fencing_token
    }

    pub const fn status(&self) -> WorkClaimStatus {
        self.status
    }

    pub const fn claimed_at(&self) -> i64 {
        self.claimed_at
    }

    pub const fn lease_expires_at(&self) -> i64 {
        self.lease_expires_at
    }

    /// Whether this claim is still the live, enforceable hold on its route
    /// at `now` -- active status alone is not enough, since a lease can
    /// lapse before anything explicitly marks the row `Expired`.
    pub const fn is_current(&self, now: i64) -> bool {
        matches!(self.status, WorkClaimStatus::Active) && self.lease_expires_at > now
    }
}

pub trait WorkClaimRepository: Send + Sync {
    /// Atomically claims `route_id` for `(worker_service, worker_instance)`
    /// through `lease_expires_at`. Fails as [`WorkClaimError::RouteNotFound`]
    /// if the route does not exist or is not assigned to `worker_service` --
    /// the two are indistinguishable to the caller, matching how disabling
    /// another service's subscription looks identical to disabling one that
    /// does not exist. Fails as [`WorkClaimError::AlreadyClaimed`] if a
    /// current (unexpired, still-`Active`) claim already exists. Otherwise
    /// supersedes whatever claim previously existed (there is always at most
    /// one row transitioning here) and mints a new claim one fencing token
    /// higher.
    fn claim(
        &self,
        route_id: RouteId,
        worker_service: ActorId,
        worker_instance: InstanceId,
        lease_expires_at: i64,
        now: i64,
    ) -> Result<WorkClaim, WorkClaimError>;

    /// Atomically extends the lease on `claim_id`, if `fencing_token`
    /// matches its current, still-active fencing token. A mismatched
    /// token -- including one that was current but has since been
    /// superseded -- fails as [`WorkClaimError::Fenced`].
    fn renew(
        &self,
        claim_id: ClaimId,
        fencing_token: i64,
        lease_expires_at: i64,
        now: i64,
    ) -> Result<WorkClaim, WorkClaimError>;

    /// Atomically releases `claim_id` so another worker can claim its route
    /// immediately, without waiting for the lease to lapse.
    fn release(
        &self,
        claim_id: ClaimId,
        fencing_token: i64,
        now: i64,
    ) -> Result<WorkClaim, WorkClaimError>;

    /// Atomically marks `claim_id` as the one that finished the work.
    /// Fails as [`WorkClaimError::Fenced`] for a stale holder exactly like
    /// `renew`/`release` do.
    fn complete(
        &self,
        claim_id: ClaimId,
        fencing_token: i64,
        now: i64,
    ) -> Result<WorkClaim, WorkClaimError>;

    fn find(&self, claim_id: ClaimId) -> Result<Option<WorkClaim>, WorkClaimError>;

    /// Returns which of `route_ids` currently have a live, unexpired
    /// active claim -- the read an eligible-route query (ADR-0011) uses to
    /// exclude routes that are already being worked. A route absent from
    /// the returned set is eligible to claim.
    fn active_route_ids(
        &self,
        route_ids: &[RouteId],
        now: i64,
    ) -> Result<HashSet<RouteId>, WorkClaimError>;
}

#[derive(Clone)]
pub struct WorkClaimService<R> {
    repository: R,
}

impl<R> WorkClaimService<R>
where
    R: WorkClaimRepository,
{
    pub const fn new(repository: R) -> Self {
        Self { repository }
    }

    pub fn claim(
        &self,
        route_id: RouteId,
        worker_service: ActorId,
        worker_instance: InstanceId,
        lease_expires_at: i64,
        now: i64,
    ) -> Result<WorkClaim, WorkClaimError> {
        if now < 0 || lease_expires_at <= now {
            return Err(WorkClaimError::InvalidLease);
        }
        self.repository.claim(
            route_id,
            worker_service,
            worker_instance,
            lease_expires_at,
            now,
        )
    }

    pub fn renew(
        &self,
        claim_id: ClaimId,
        fencing_token: i64,
        lease_expires_at: i64,
        now: i64,
    ) -> Result<WorkClaim, WorkClaimError> {
        if now < 0 || lease_expires_at <= now {
            return Err(WorkClaimError::InvalidLease);
        }
        self.repository
            .renew(claim_id, fencing_token, lease_expires_at, now)
    }

    pub fn release(
        &self,
        claim_id: ClaimId,
        fencing_token: i64,
        now: i64,
    ) -> Result<WorkClaim, WorkClaimError> {
        if now < 0 {
            return Err(WorkClaimError::InvalidLease);
        }
        self.repository.release(claim_id, fencing_token, now)
    }

    pub fn complete(
        &self,
        claim_id: ClaimId,
        fencing_token: i64,
        now: i64,
    ) -> Result<WorkClaim, WorkClaimError> {
        if now < 0 {
            return Err(WorkClaimError::InvalidLease);
        }
        self.repository.complete(claim_id, fencing_token, now)
    }

    pub fn find(&self, claim_id: ClaimId) -> Result<Option<WorkClaim>, WorkClaimError> {
        self.repository.find(claim_id)
    }

    pub fn active_route_ids(
        &self,
        route_ids: &[RouteId],
        now: i64,
    ) -> Result<HashSet<RouteId>, WorkClaimError> {
        if now < 0 {
            return Err(WorkClaimError::InvalidTimestamp);
        }
        self.repository.active_route_ids(route_ids, now)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorkClaimError {
    InvalidClaimId,
    InvalidFencingToken,
    InvalidLease,
    InvalidTimestamp,
    RouteNotFound(RouteId),
    AlreadyClaimed(RouteId),
    NotFound(ClaimId),
    Fenced,
    Repository(String),
}

impl Display for WorkClaimError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidClaimId => formatter.write_str("claim ID must be a UUID"),
            Self::InvalidFencingToken => {
                formatter.write_str("fencing token must be a positive integer")
            }
            Self::InvalidLease => formatter.write_str("claim lease window is invalid"),
            Self::InvalidTimestamp => formatter.write_str("timestamp must not be negative"),
            Self::RouteNotFound(id) => write!(formatter, "route {id} was not found"),
            Self::AlreadyClaimed(id) => write!(formatter, "route {id} is already claimed"),
            Self::NotFound(id) => write!(formatter, "claim {id} was not found"),
            Self::Fenced => {
                formatter.write_str("fencing token does not match the current active claim")
            }
            Self::Repository(message) => {
                write!(formatter, "work claim repository failed: {message}")
            }
        }
    }
}

impl Error for WorkClaimError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn traces_to_work_claims_requirement() {
        assert_eq!(REQUIREMENT.id, "ILK-011");
        assert_eq!(REQUIREMENT.capability, "Work claims");
    }

    fn claim(fencing_token: i64, status: WorkClaimStatus, lease_expires_at: i64) -> WorkClaim {
        WorkClaim::restore(
            ClaimId::new(),
            RouteId::new(),
            ActorId::new(),
            InstanceId::new(),
            fencing_token,
            status,
            0,
            lease_expires_at,
        )
        .unwrap()
    }

    #[test]
    fn an_active_unexpired_claim_is_current() {
        let claim = claim(1, WorkClaimStatus::Active, 100);
        assert!(claim.is_current(50));
        assert!(!claim.is_current(100));
        assert!(!claim.is_current(150));
    }

    #[test]
    fn a_completed_or_released_claim_is_never_current_even_before_its_lease_ends() {
        assert!(!claim(1, WorkClaimStatus::Completed, 100).is_current(10));
        assert!(!claim(1, WorkClaimStatus::Released, 100).is_current(10));
        assert!(!claim(1, WorkClaimStatus::Expired, 100).is_current(10));
    }

    #[test]
    fn rejects_a_non_positive_fencing_token() {
        assert_eq!(
            WorkClaim::restore(
                ClaimId::new(),
                RouteId::new(),
                ActorId::new(),
                InstanceId::new(),
                0,
                WorkClaimStatus::Active,
                0,
                10,
            ),
            Err(WorkClaimError::InvalidFencingToken)
        );
    }

    #[test]
    fn rejects_a_lease_that_does_not_extend_past_claimed_at() {
        assert_eq!(
            WorkClaim::restore(
                ClaimId::new(),
                RouteId::new(),
                ActorId::new(),
                InstanceId::new(),
                1,
                WorkClaimStatus::Active,
                10,
                10,
            ),
            Err(WorkClaimError::InvalidLease)
        );
    }
}
