//! Goal: atomically reserve signed-request nonces and stable request IDs using
//! fixed PostgreSQL statements while retaining append-only security outcomes.

use r2d2_postgres::postgres::Transaction;

use crate::kernel::replay_protection::{
    ReplayDisposition, ReplayProtectionError, ReplayProtectionRepository, ReplayReservation,
};

use super::database::Database;

#[derive(Clone)]
pub struct PostgresReplayProtectionRepository {
    database: Database,
}

impl PostgresReplayProtectionRepository {
    pub const fn new(database: Database) -> Self {
        Self { database }
    }
}

impl ReplayProtectionRepository for PostgresReplayProtectionRepository {
    fn reserve(
        &self,
        reservation: ReplayReservation,
    ) -> Result<ReplayDisposition, ReplayProtectionError> {
        let mut connection = self.database.connection().map_err(repository_error)?;
        let mut transaction = connection.transaction().map_err(repository_error)?;
        let service_id = reservation.service_id().to_string();
        let instance_id = reservation.instance_id().to_string();
        let key_id = reservation.key_id().to_string();
        let request_id = reservation.request_id().to_string();
        let nonce_digest = reservation.nonce_digest().as_slice();
        let request_fingerprint = reservation.request_fingerprint().as_slice();

        let nonce_rows = transaction
            .execute(
                "INSERT INTO service_request_nonces \
                 (key_id, nonce_digest, service_id, instance_id, request_id, \
                  request_fingerprint, signature_created, signature_expires, reserved_at) \
                 VALUES ($1::text::uuid, $2, $3::text::uuid, $4::text::uuid, \
                         $5::text::uuid, $6, $7, $8, $9) \
                 ON CONFLICT (key_id, nonce_digest) DO NOTHING",
                &[
                    &key_id,
                    &nonce_digest,
                    &service_id,
                    &instance_id,
                    &request_id,
                    &request_fingerprint,
                    &reservation.signature_created(),
                    &reservation.signature_expires(),
                    &reservation.reserved_at(),
                ],
            )
            .map_err(repository_error)?;
        if nonce_rows == 0 {
            append_audit(&mut transaction, &reservation, "replay_rejected")?;
            transaction.commit().map_err(repository_error)?;
            return Err(ReplayProtectionError::ReplayDetected);
        }
        if nonce_rows != 1 {
            return Err(ReplayProtectionError::Repository(format!(
                "nonce reservation changed {nonce_rows} rows"
            )));
        }

        let request_rows = transaction
            .execute(
                "INSERT INTO service_request_ids \
                 (service_id, request_id, request_fingerprint, first_seen_at) \
                 VALUES ($1::text::uuid, $2::text::uuid, $3, $4) \
                 ON CONFLICT (service_id, request_id) DO NOTHING",
                &[
                    &service_id,
                    &request_id,
                    &request_fingerprint,
                    &reservation.reserved_at(),
                ],
            )
            .map_err(repository_error)?;
        let stored_fingerprint: Vec<u8> = transaction
            .query_one(
                "SELECT request_fingerprint FROM service_request_ids \
                 WHERE service_id = $1::text::uuid AND request_id = $2::text::uuid",
                &[&service_id, &request_id],
            )
            .map_err(repository_error)?
            .get(0);

        if stored_fingerprint.as_slice() != request_fingerprint {
            append_audit(&mut transaction, &reservation, "request_conflict_rejected")?;
            transaction.commit().map_err(repository_error)?;
            return Err(ReplayProtectionError::RequestIdConflict);
        }

        let disposition = if request_rows == 1 {
            ReplayDisposition::Fresh
        } else if request_rows == 0 {
            ReplayDisposition::SafeRetry
        } else {
            return Err(ReplayProtectionError::Repository(format!(
                "request ID reservation changed {request_rows} rows"
            )));
        };
        let outcome = match disposition {
            ReplayDisposition::Fresh => "fresh",
            ReplayDisposition::SafeRetry => "safe_retry",
        };
        append_audit(&mut transaction, &reservation, outcome)?;
        transaction.commit().map_err(repository_error)?;
        Ok(disposition)
    }
}

fn append_audit(
    transaction: &mut Transaction<'_>,
    reservation: &ReplayReservation,
    outcome: &str,
) -> Result<(), ReplayProtectionError> {
    transaction
        .execute(
            "INSERT INTO service_request_replay_audit \
             (service_id, instance_id, key_id, request_id, nonce_digest, \
              request_fingerprint, outcome, recorded_at) \
             VALUES ($1::text::uuid, $2::text::uuid, $3::text::uuid, \
                     $4::text::uuid, $5, $6, $7, $8)",
            &[
                &reservation.service_id().to_string(),
                &reservation.instance_id().to_string(),
                &reservation.key_id().to_string(),
                &reservation.request_id().to_string(),
                &reservation.nonce_digest().as_slice(),
                &reservation.request_fingerprint().as_slice(),
                &outcome,
                &reservation.reserved_at(),
            ],
        )
        .map_err(repository_error)?;
    Ok(())
}

fn repository_error(error: impl std::fmt::Display) -> ReplayProtectionError {
    ReplayProtectionError::Repository(error.to_string())
}
