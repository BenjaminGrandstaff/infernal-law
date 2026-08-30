//! Goal: define a strict JSON wire format for renewing an already-enrolled
//! instance's own lease, mirroring the request/response shapes already used
//! for enrollment (`enrollment_dto`) and work-claim renewal
//! (`work_claim_dto`).

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstanceRenewalRequest {
    expected_revision: i64,
}

impl InstanceRenewalRequest {
    pub const fn expected_revision(&self) -> i64 {
        self.expected_revision
    }
}
