//! Goal: persist the administrator-controlled Kubernetes workload-to-service
//! enrollment mapping with fixed, parameterized SQL only.

use r2d2_postgres::postgres::error::SqlState;

use crate::kernel::enrollment::EnrollmentChallenge;
use crate::kernel::enrollment::{EnrollmentBinding, EnrollmentBindingRepository, EnrollmentError};
use crate::kernel::identity::ActorId;
use sha2::{Digest, Sha256};

use super::database::Database;

#[derive(Clone)]
pub struct PostgresEnrollmentBindingRepository {
    database: Database,
}

impl PostgresEnrollmentBindingRepository {
    pub const fn new(database: Database) -> Self {
        Self { database }
    }
}

impl EnrollmentBindingRepository for PostgresEnrollmentBindingRepository {
    fn insert_disabled(&self, binding: EnrollmentBinding) -> Result<(), EnrollmentError> {
        let mut connection = self.database.connection().map_err(repository_error)?;
        connection
            .execute(
                "INSERT INTO service_enrollment_bindings \
             (service_id, namespace, service_account, service_account_uid, enabled) \
             VALUES ($1::text::uuid, $2, $3, $4, false)",
                &[
                    &binding.service_id().to_string(),
                    &binding.namespace(),
                    &binding.service_account(),
                    &binding.service_account_uid(),
                ],
            )
            .map_err(|error| {
                if error.code() == Some(&SqlState::UNIQUE_VIOLATION) {
                    EnrollmentError::Repository("enrollment binding already exists".to_owned())
                } else if error.code() == Some(&SqlState::FOREIGN_KEY_VIOLATION) {
                    EnrollmentError::Repository("service identity was not found".to_owned())
                } else {
                    repository_error(error)
                }
            })?;
        Ok(())
    }

    fn set_enabled(&self, service_id: ActorId, enabled: bool) -> Result<(), EnrollmentError> {
        let mut connection = self.database.connection().map_err(repository_error)?;
        let rows = connection
            .execute(
                "UPDATE service_enrollment_bindings SET enabled = $2, updated_at = now() \
             WHERE service_id = $1::text::uuid",
                &[&service_id.to_string(), &enabled],
            )
            .map_err(repository_error)?;
        if rows != 1 {
            return Err(EnrollmentError::BindingNotFound);
        }
        Ok(())
    }

    fn find_workload(
        &self,
        namespace: &str,
        service_account: &str,
        service_account_uid: &str,
    ) -> Result<Option<EnrollmentBinding>, EnrollmentError> {
        let mut connection = self.database.connection().map_err(repository_error)?;
        connection
            .query_opt(
                "SELECT service_id::text, namespace, service_account, \
                    service_account_uid, enabled \
             FROM service_enrollment_bindings \
             WHERE namespace = $1 AND service_account = $2 AND service_account_uid = $3",
                &[&namespace, &service_account, &service_account_uid],
            )
            .map_err(repository_error)?
            .map(|row| {
                let service_id = row
                    .get::<_, String>(0)
                    .parse::<ActorId>()
                    .map_err(|error| {
                        EnrollmentError::Repository(format!("invalid stored service ID: {error}"))
                    })?;
                EnrollmentBinding::restore(
                    service_id,
                    row.get::<_, String>(1).as_str(),
                    row.get::<_, String>(2).as_str(),
                    row.get::<_, String>(3).as_str(),
                    row.get(4),
                )
                .map_err(|_| {
                    EnrollmentError::Repository("stored enrollment binding is invalid".to_owned())
                })
            })
            .transpose()
    }

    fn insert_challenge(
        &self,
        service_id: ActorId,
        challenge: EnrollmentChallenge,
        expires_at: i64,
    ) -> Result<(), EnrollmentError> {
        let digest: [u8; 32] = Sha256::digest(challenge.as_bytes()).into();
        let mut connection = self.database.connection().map_err(repository_error)?;
        connection
            .execute(
                "INSERT INTO service_enrollment_challenges \
             (challenge_digest, service_id, expires_at) VALUES ($1, $2::text::uuid, $3)",
                &[&digest.as_slice(), &service_id.to_string(), &expires_at],
            )
            .map_err(repository_error)?;
        Ok(())
    }

    fn consume_challenge(
        &self,
        service_id: ActorId,
        challenge: EnrollmentChallenge,
        now: i64,
    ) -> Result<(), EnrollmentError> {
        let digest: [u8; 32] = Sha256::digest(challenge.as_bytes()).into();
        let mut connection = self.database.connection().map_err(repository_error)?;
        let rows = connection
            .execute(
                "UPDATE service_enrollment_challenges SET consumed_at = $3 \
             WHERE challenge_digest = $1 AND service_id = $2::text::uuid \
               AND consumed_at IS NULL AND expires_at > $3",
                &[&digest.as_slice(), &service_id.to_string(), &now],
            )
            .map_err(repository_error)?;
        if rows != 1 {
            return Err(EnrollmentError::ChallengeRejected);
        }
        Ok(())
    }
}

fn repository_error(error: impl std::fmt::Display) -> EnrollmentError {
    EnrollmentError::Repository(error.to_string())
}
