//! Goal: atomically persist ILK-011 work claims with fixed, parameterized
//! SQL -- exactly one current claim per route, a monotonically increasing
//! fencing token per route, and a status that transitions at most once away
//! from `active`, enforced structurally by `protect_work_claim()` in
//! migration 0017, not merely by convention here.

use std::collections::HashSet;

use r2d2_postgres::postgres::{Row, Transaction};

use crate::kernel::identity::ActorId;
use crate::kernel::instance_keys::InstanceId;
use crate::kernel::requests::RouteId;
use crate::kernel::work_claims::{
    ClaimId, WorkClaim, WorkClaimError, WorkClaimRepository, WorkClaimStatus,
};

use super::database::Database;

const ROUTE_DESTINATION_SQL: &str =
    "SELECT destination_service_id::text FROM request_routes WHERE route_id = $1::text::uuid";
const LOCK_LATEST_CLAIM_FOR_ROUTE_SQL: &str = "SELECT claim_id::text, route_id::text, \
        worker_service_id::text, worker_instance_id::text, fencing_token, status, \
        claimed_at, lease_expires_at \
    FROM work_claims WHERE route_id = $1::text::uuid \
    ORDER BY fencing_token DESC LIMIT 1 FOR UPDATE";
const EXPIRE_SQL: &str =
    "UPDATE work_claims SET status = 'expired' WHERE claim_id = $1::text::uuid";
const INSERT_CLAIM_SQL: &str = "INSERT INTO work_claims \
    (claim_id, route_id, worker_service_id, worker_instance_id, fencing_token, status, \
     claimed_at, lease_expires_at) \
    VALUES ($1::text::uuid, $2::text::uuid, $3::text::uuid, $4::text::uuid, $5, 'active', $6, $7) \
    RETURNING claim_id::text, route_id::text, worker_service_id::text, worker_instance_id::text, \
              fencing_token, status, claimed_at, lease_expires_at";
const LOCK_CLAIM_BY_ID_SQL: &str = "SELECT claim_id::text, route_id::text, \
        worker_service_id::text, worker_instance_id::text, fencing_token, status, \
        claimed_at, lease_expires_at \
    FROM work_claims WHERE claim_id = $1::text::uuid FOR UPDATE";
const FIND_CLAIM_BY_ID_SQL: &str = "SELECT claim_id::text, route_id::text, \
        worker_service_id::text, worker_instance_id::text, fencing_token, status, \
        claimed_at, lease_expires_at \
    FROM work_claims WHERE claim_id = $1::text::uuid";
const RENEW_SQL: &str = "UPDATE work_claims SET lease_expires_at = $2 \
    WHERE claim_id = $1::text::uuid \
    RETURNING claim_id::text, route_id::text, worker_service_id::text, worker_instance_id::text, \
              fencing_token, status, claimed_at, lease_expires_at";
const TRANSITION_SQL: &str = "UPDATE work_claims SET status = $2 WHERE claim_id = $1::text::uuid \
    RETURNING claim_id::text, route_id::text, worker_service_id::text, worker_instance_id::text, \
              fencing_token, status, claimed_at, lease_expires_at";
const ACTIVE_ROUTE_IDS_SQL: &str = "SELECT DISTINCT route_id::text FROM work_claims \
    WHERE route_id::text = ANY($1) AND status = 'active' AND lease_expires_at > $2";
const COMPLETED_ROUTE_IDS_SQL: &str = "SELECT DISTINCT route_id::text FROM work_claims \
    WHERE route_id::text = ANY($1) AND status = 'completed'";

#[derive(Clone)]
pub struct PostgresWorkClaimRepository {
    database: Database,
}

impl PostgresWorkClaimRepository {
    pub const fn new(database: Database) -> Self {
        Self { database }
    }
}

impl WorkClaimRepository for PostgresWorkClaimRepository {
    fn claim(
        &self,
        route_id: RouteId,
        worker_service: ActorId,
        worker_instance: InstanceId,
        lease_expires_at: i64,
        now: i64,
    ) -> Result<WorkClaim, WorkClaimError> {
        let mut connection = self.database.connection().map_err(repository_error)?;
        let mut transaction = connection.transaction().map_err(repository_error)?;
        let route_id_text = route_id.to_string();

        let destination = transaction
            .query_opt(ROUTE_DESTINATION_SQL, &[&route_id_text])
            .map_err(repository_error)?;
        let owns_route = match destination {
            Some(row) => {
                row.get::<_, String>("destination_service_id")
                    .parse::<ActorId>()
                    .map_err(|error| {
                        WorkClaimError::Repository(format!(
                            "invalid stored destination ID: {error}"
                        ))
                    })?
                    == worker_service
            }
            None => false,
        };
        if !owns_route {
            return Err(WorkClaimError::RouteNotFound(route_id));
        }

        let latest = transaction
            .query_opt(LOCK_LATEST_CLAIM_FOR_ROUTE_SQL, &[&route_id_text])
            .map_err(repository_error)?
            .map(|row| claim_from_row(&row))
            .transpose()?;
        let next_fencing_token = match &latest {
            Some(claim) if claim.is_current(now) => {
                return Err(WorkClaimError::AlreadyClaimed(route_id));
            }
            // A route's completion is permanent, unlike an active claim's
            // lease -- checked ahead of any expiry timing so a completed
            // route is never reclaimable no matter how much time has
            // passed. Confirmed live: without this, a route whose only
            // claim had already completed (not merely expired) was
            // reclaimable indefinitely.
            Some(claim) if matches!(claim.status(), WorkClaimStatus::Completed) => {
                return Err(WorkClaimError::AlreadyCompleted(route_id));
            }
            Some(claim) => {
                if matches!(claim.status(), WorkClaimStatus::Active) {
                    transaction
                        .execute(EXPIRE_SQL, &[&claim.id().to_string()])
                        .map_err(repository_error)?;
                }
                claim.fencing_token() + 1
            }
            None => 1,
        };

        let claim_id = ClaimId::new().to_string();
        let worker_service_text = worker_service.to_string();
        let worker_instance_text = worker_instance.to_string();
        let row = transaction
            .query_one(
                INSERT_CLAIM_SQL,
                &[
                    &claim_id,
                    &route_id_text,
                    &worker_service_text,
                    &worker_instance_text,
                    &next_fencing_token,
                    &now,
                    &lease_expires_at,
                ],
            )
            .map_err(repository_error)?;
        let claim = claim_from_row(&row)?;
        transaction.commit().map_err(repository_error)?;
        Ok(claim)
    }

    fn renew(
        &self,
        claim_id: ClaimId,
        fencing_token: i64,
        lease_expires_at: i64,
        now: i64,
    ) -> Result<WorkClaim, WorkClaimError> {
        let mut connection = self.database.connection().map_err(repository_error)?;
        let mut transaction = connection.transaction().map_err(repository_error)?;
        let current = lock_current(&mut transaction, claim_id, fencing_token, now)?;
        let row = transaction
            .query_one(RENEW_SQL, &[&current.id().to_string(), &lease_expires_at])
            .map_err(repository_error)?;
        let claim = claim_from_row(&row)?;
        transaction.commit().map_err(repository_error)?;
        Ok(claim)
    }

    fn release(
        &self,
        claim_id: ClaimId,
        fencing_token: i64,
        now: i64,
    ) -> Result<WorkClaim, WorkClaimError> {
        self.transition(claim_id, fencing_token, now, "released")
    }

    fn complete(
        &self,
        claim_id: ClaimId,
        fencing_token: i64,
        now: i64,
    ) -> Result<WorkClaim, WorkClaimError> {
        self.transition(claim_id, fencing_token, now, "completed")
    }

    fn find(&self, claim_id: ClaimId) -> Result<Option<WorkClaim>, WorkClaimError> {
        let mut connection = self.database.connection().map_err(repository_error)?;
        connection
            .query_opt(FIND_CLAIM_BY_ID_SQL, &[&claim_id.to_string()])
            .map_err(repository_error)?
            .as_ref()
            .map(claim_from_row)
            .transpose()
    }

    fn active_route_ids(
        &self,
        route_ids: &[RouteId],
        now: i64,
    ) -> Result<HashSet<RouteId>, WorkClaimError> {
        if route_ids.is_empty() {
            return Ok(HashSet::new());
        }
        let route_ids: Vec<String> = route_ids.iter().map(ToString::to_string).collect();
        let mut connection = self.database.connection().map_err(repository_error)?;
        connection
            .query(ACTIVE_ROUTE_IDS_SQL, &[&route_ids, &now])
            .map_err(repository_error)?
            .iter()
            .map(|row| {
                row.get::<_, String>("route_id")
                    .parse::<RouteId>()
                    .map_err(|_| {
                        WorkClaimError::Repository("stored route ID is invalid".to_owned())
                    })
            })
            .collect()
    }

    fn completed_route_ids(
        &self,
        route_ids: &[RouteId],
    ) -> Result<HashSet<RouteId>, WorkClaimError> {
        if route_ids.is_empty() {
            return Ok(HashSet::new());
        }
        let route_ids: Vec<String> = route_ids.iter().map(ToString::to_string).collect();
        let mut connection = self.database.connection().map_err(repository_error)?;
        connection
            .query(COMPLETED_ROUTE_IDS_SQL, &[&route_ids])
            .map_err(repository_error)?
            .iter()
            .map(|row| {
                row.get::<_, String>("route_id")
                    .parse::<RouteId>()
                    .map_err(|_| {
                        WorkClaimError::Repository("stored route ID is invalid".to_owned())
                    })
            })
            .collect()
    }
}

impl PostgresWorkClaimRepository {
    fn transition(
        &self,
        claim_id: ClaimId,
        fencing_token: i64,
        now: i64,
        status: &str,
    ) -> Result<WorkClaim, WorkClaimError> {
        let mut connection = self.database.connection().map_err(repository_error)?;
        let mut transaction = connection.transaction().map_err(repository_error)?;
        let current = lock_current(&mut transaction, claim_id, fencing_token, now)?;
        let row = transaction
            .query_one(TRANSITION_SQL, &[&current.id().to_string(), &status])
            .map_err(repository_error)?;
        let claim = claim_from_row(&row)?;
        transaction.commit().map_err(repository_error)?;
        Ok(claim)
    }
}

/// Locks and returns the claim `claim_id` names, only if `fencing_token`
/// matches and it is still current at `now` -- otherwise the caller has
/// already lost the claim, whether by expiry, release, completion, or a
/// later claim superseding it.
fn lock_current(
    transaction: &mut Transaction<'_>,
    claim_id: ClaimId,
    fencing_token: i64,
    now: i64,
) -> Result<WorkClaim, WorkClaimError> {
    let row = transaction
        .query_opt(LOCK_CLAIM_BY_ID_SQL, &[&claim_id.to_string()])
        .map_err(repository_error)?
        .ok_or(WorkClaimError::NotFound(claim_id))?;
    let claim = claim_from_row(&row)?;
    if claim.fencing_token() != fencing_token || !claim.is_current(now) {
        return Err(WorkClaimError::Fenced);
    }
    Ok(claim)
}

fn claim_from_row(row: &Row) -> Result<WorkClaim, WorkClaimError> {
    let id = row.get::<_, String>("claim_id").parse::<ClaimId>()?;
    let route_id = row
        .get::<_, String>("route_id")
        .parse::<RouteId>()
        .map_err(|_| WorkClaimError::Repository("stored route ID is invalid".to_owned()))?;
    let worker_service = row
        .get::<_, String>("worker_service_id")
        .parse::<ActorId>()
        .map_err(|error| {
            WorkClaimError::Repository(format!("invalid stored worker service ID: {error}"))
        })?;
    let worker_instance = row
        .get::<_, String>("worker_instance_id")
        .parse::<InstanceId>()
        .map_err(|_| {
            WorkClaimError::Repository("stored worker instance ID is invalid".to_owned())
        })?;
    let status = status_from_sql(row.get("status"))?;
    WorkClaim::restore(
        id,
        route_id,
        worker_service,
        worker_instance,
        row.get("fencing_token"),
        status,
        row.get("claimed_at"),
        row.get("lease_expires_at"),
    )
    .map_err(|_| WorkClaimError::Repository("stored work claim is invalid".to_owned()))
}

fn status_from_sql(value: &str) -> Result<WorkClaimStatus, WorkClaimError> {
    match value {
        "active" => Ok(WorkClaimStatus::Active),
        "completed" => Ok(WorkClaimStatus::Completed),
        "released" => Ok(WorkClaimStatus::Released),
        "expired" => Ok(WorkClaimStatus::Expired),
        other => Err(WorkClaimError::Repository(format!(
            "unknown stored work claim status: {other}"
        ))),
    }
}

fn repository_error(error: impl std::fmt::Display) -> WorkClaimError {
    WorkClaimError::Repository(error.to_string())
}
