//! Goal: define the ILK-011 work-claim JSON wire format, kept separate
//! from HTTP status/error-code mapping (`src/http.rs`) the same way the
//! other DTO modules separate their wire shapes from dispatch.

use serde::{Deserialize, Serialize};

use crate::kernel::work_claims::{WorkClaim, WorkClaimStatus};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimRequest {
    lease_seconds: i64,
}

impl ClaimRequest {
    /// Computes an absolute lease deadline from `now` -- the kernel's own
    /// clock, never a caller-supplied timestamp, decides when a lease
    /// actually expires.
    pub fn lease_expires_at(&self, now: i64) -> Option<i64> {
        now.checked_add(self.lease_seconds)
            .filter(|value| *value > now)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RenewRequest {
    fencing_token: i64,
    lease_seconds: i64,
}

impl RenewRequest {
    pub const fn fencing_token(&self) -> i64 {
        self.fencing_token
    }

    pub fn lease_expires_at(&self, now: i64) -> Option<i64> {
        now.checked_add(self.lease_seconds)
            .filter(|value| *value > now)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FencedActionRequest {
    fencing_token: i64,
}

impl FencedActionRequest {
    pub const fn fencing_token(&self) -> i64 {
        self.fencing_token
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WorkClaimResponse {
    pub claim_id: String,
    pub route_id: String,
    pub worker_service_id: String,
    pub worker_instance_id: String,
    pub fencing_token: i64,
    pub status: String,
    pub claimed_at: i64,
    pub lease_expires_at: i64,
}

impl From<&WorkClaim> for WorkClaimResponse {
    fn from(claim: &WorkClaim) -> Self {
        Self {
            claim_id: claim.id().to_string(),
            route_id: claim.route_id().to_string(),
            worker_service_id: claim.worker_service().to_string(),
            worker_instance_id: claim.worker_instance().to_string(),
            fencing_token: claim.fencing_token(),
            status: status_str(claim.status()).to_owned(),
            claimed_at: claim.claimed_at(),
            lease_expires_at: claim.lease_expires_at(),
        }
    }
}

fn status_str(status: WorkClaimStatus) -> &'static str {
    match status {
        WorkClaimStatus::Active => "active",
        WorkClaimStatus::Completed => "completed",
        WorkClaimStatus::Released => "released",
        WorkClaimStatus::Expired => "expired",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unknown_fields_in_claim_requests() {
        let result: Result<ClaimRequest, _> =
            serde_json::from_str(r#"{"lease_seconds":30,"extra":true}"#);
        assert!(result.is_err());
    }

    #[test]
    fn lease_expires_at_is_computed_from_the_kernels_own_clock() {
        let dto: ClaimRequest = serde_json::from_str(r#"{"lease_seconds":30}"#).unwrap();
        assert_eq!(dto.lease_expires_at(100), Some(130));
    }

    #[test]
    fn a_non_positive_lease_duration_is_rejected() {
        let dto: ClaimRequest = serde_json::from_str(r#"{"lease_seconds":0}"#).unwrap();
        assert_eq!(dto.lease_expires_at(100), None);

        let negative: ClaimRequest = serde_json::from_str(r#"{"lease_seconds":-5}"#).unwrap();
        assert_eq!(negative.lease_expires_at(100), None);
    }

    #[test]
    fn parses_renew_and_fenced_action_requests() {
        let renew: RenewRequest =
            serde_json::from_str(r#"{"fencing_token":3,"lease_seconds":30}"#).unwrap();
        assert_eq!(renew.fencing_token(), 3);
        assert_eq!(renew.lease_expires_at(10), Some(40));

        let fenced: FencedActionRequest = serde_json::from_str(r#"{"fencing_token":3}"#).unwrap();
        assert_eq!(fenced.fencing_token(), 3);
    }
}
