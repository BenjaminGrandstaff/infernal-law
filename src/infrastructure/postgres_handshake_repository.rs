//! Goal: persist signed challenge consumption and append-only successful
//! handshake history with fixed, parameterized PostgreSQL statements.

use r2d2_postgres::postgres::Row;

use crate::kernel::handshakes::{
    HandshakeChallengeRecord, HandshakeError, HandshakeRepository, InstanceHandshake,
};
use crate::kernel::instance_keys::{InstanceId, KeyId};

use super::database::Database;

#[derive(Clone)]
pub struct PostgresHandshakeRepository {
    database: Database,
}

impl PostgresHandshakeRepository {
    pub const fn new(database: Database) -> Self {
        Self { database }
    }
}

impl HandshakeRepository for PostgresHandshakeRepository {
    fn insert_challenge(&self, challenge: HandshakeChallengeRecord) -> Result<(), HandshakeError> {
        let mut connection = self.database.connection().map_err(repository_error)?;
        let mut transaction = connection.transaction().map_err(repository_error)?;
        transaction
            .execute(
                "INSERT INTO service_instance_handshake_challenges \
             (challenge_digest, kernel_instance_id, target_instance_id, target_key_id, \
              issued_at, expires_at) \
             VALUES ($1, $2::text::uuid, $3::text::uuid, $4::text::uuid, $5, $6)",
                &[
                    &challenge.digest().as_slice(),
                    &challenge.kernel_instance_id().to_string(),
                    &challenge.target_instance_id().to_string(),
                    &challenge.target_key_id().to_string(),
                    &challenge.issued_at(),
                    &challenge.expires_at(),
                ],
            )
            .map_err(repository_error)?;
        append_audit(
            &mut transaction,
            challenge.digest(),
            challenge.kernel_instance_id(),
            challenge.target_instance_id(),
            "issued",
            challenge.issued_at(),
        )?;
        transaction.commit().map_err(repository_error)
    }

    fn complete(&self, handshake: InstanceHandshake) -> Result<(), HandshakeError> {
        let mut connection = self.database.connection().map_err(repository_error)?;
        let mut transaction = connection.transaction().map_err(repository_error)?;
        let rows = transaction
            .execute(
                "UPDATE service_instance_handshake_challenges SET consumed_at = $4 \
             WHERE challenge_digest = $1 \
               AND kernel_instance_id = $2::text::uuid \
               AND target_instance_id = $3::text::uuid \
               AND consumed_at IS NULL AND expires_at > $4",
                &[
                    &handshake.challenge_digest().as_slice(),
                    &handshake.kernel_instance_id().to_string(),
                    &handshake.target_instance_id().to_string(),
                    &handshake.verified_at(),
                ],
            )
            .map_err(repository_error)?;
        if rows != 1 {
            return Err(HandshakeError::ChallengeAlreadyUsed);
        }
        transaction
            .execute(
                "INSERT INTO service_instance_handshakes \
             (challenge_digest, kernel_instance_id, target_instance_id, target_key_id, \
              verified_at, expires_at) \
             VALUES ($1, $2::text::uuid, $3::text::uuid, $4::text::uuid, $5, $6)",
                &[
                    &handshake.challenge_digest().as_slice(),
                    &handshake.kernel_instance_id().to_string(),
                    &handshake.target_instance_id().to_string(),
                    &handshake.target_key_id().to_string(),
                    &handshake.verified_at(),
                    &handshake.expires_at(),
                ],
            )
            .map_err(repository_error)?;
        append_audit(
            &mut transaction,
            handshake.challenge_digest(),
            handshake.kernel_instance_id(),
            handshake.target_instance_id(),
            "verified",
            handshake.verified_at(),
        )?;
        transaction.commit().map_err(repository_error)
    }

    fn find_fresh(
        &self,
        kernel_instance_id: InstanceId,
        target_instance_id: InstanceId,
        now: i64,
    ) -> Result<Option<InstanceHandshake>, HandshakeError> {
        if now < 0 {
            return Err(HandshakeError::InvalidTimestamp);
        }
        let mut connection = self.database.connection().map_err(repository_error)?;
        connection
            .query_opt(
                "SELECT challenge_digest, kernel_instance_id::text, target_instance_id::text, \
                    target_key_id::text, verified_at, expires_at \
             FROM service_instance_handshakes \
             WHERE kernel_instance_id = $1::text::uuid \
               AND target_instance_id = $2::text::uuid \
               AND verified_at <= $3 AND expires_at > $3 \
             ORDER BY verified_at DESC LIMIT 1",
                &[
                    &kernel_instance_id.to_string(),
                    &target_instance_id.to_string(),
                    &now,
                ],
            )
            .map_err(repository_error)?
            .as_ref()
            .map(handshake_from_row)
            .transpose()
    }
}

fn append_audit(
    transaction: &mut r2d2_postgres::postgres::Transaction<'_>,
    digest: &[u8; 32],
    kernel_instance_id: InstanceId,
    target_instance_id: InstanceId,
    action: &str,
    recorded_at: i64,
) -> Result<(), HandshakeError> {
    transaction
        .execute(
            "INSERT INTO service_instance_handshake_audit \
         (challenge_digest, kernel_instance_id, target_instance_id, action, recorded_at) \
         VALUES ($1, $2::text::uuid, $3::text::uuid, $4, $5)",
            &[
                &digest.as_slice(),
                &kernel_instance_id.to_string(),
                &target_instance_id.to_string(),
                &action,
                &recorded_at,
            ],
        )
        .map_err(repository_error)?;
    Ok(())
}

fn handshake_from_row(row: &Row) -> Result<InstanceHandshake, HandshakeError> {
    let digest: [u8; 32] = row
        .get::<_, Vec<u8>>("challenge_digest")
        .try_into()
        .map_err(|_| HandshakeError::InvalidStoredRecord)?;
    let kernel_instance_id = row
        .get::<_, String>("kernel_instance_id")
        .parse::<InstanceId>()
        .map_err(|_| HandshakeError::InvalidStoredRecord)?;
    let target_instance_id = row
        .get::<_, String>("target_instance_id")
        .parse::<InstanceId>()
        .map_err(|_| HandshakeError::InvalidStoredRecord)?;
    let target_key_id = row
        .get::<_, String>("target_key_id")
        .parse::<KeyId>()
        .map_err(|_| HandshakeError::InvalidStoredRecord)?;
    InstanceHandshake::restore(
        digest,
        kernel_instance_id,
        target_instance_id,
        target_key_id,
        row.get("verified_at"),
        row.get("expires_at"),
    )
}

fn repository_error(error: impl std::fmt::Display) -> HandshakeError {
    HandshakeError::Repository(error.to_string())
}
