//! Goal: persist public instance keys and leases with fixed, parameterized SQL
//! while keeping private keys and caller-supplied SQL outside PostgreSQL.

use r2d2_postgres::postgres::{Error as PostgresError, Row, error::SqlState};

use crate::kernel::identity::ActorId;
use crate::kernel::instance_keys::{InstanceId, InstancePublicKey, KeyId, PUBLIC_KEY_LENGTH};
use crate::kernel::instance_registry::{
    InstanceRegistryError, InstanceRegistryRepository, RegisteredInstance,
};

use super::database::Database;

const FIND_INSTANCE_SQL: &str = "SELECT si.service_id::text AS service_id, \
            si.instance_id::text AS instance_id, si.endpoint, \
            si.registered_at, si.lease_expires_at, si.lease_revision, \
            si.revoked_at, sik.key_id::text AS key_id, sik.public_key \
     FROM service_instances si \
     JOIN service_instance_keys sik ON sik.instance_id = si.instance_id \
     WHERE si.instance_id = $1::text::uuid";

#[derive(Clone)]
pub struct PostgresInstanceRegistry {
    database: Database,
}

impl PostgresInstanceRegistry {
    pub const fn new(database: Database) -> Self {
        Self { database }
    }
}

impl InstanceRegistryRepository for PostgresInstanceRegistry {
    fn insert(&self, instance: RegisteredInstance) -> Result<(), InstanceRegistryError> {
        let mut connection = self.database.connection().map_err(repository_error)?;
        let mut transaction = connection.transaction().map_err(repository_error)?;
        let public = instance.public_key();
        let service_id = public.service_id().to_string();
        let instance_id = public.instance_id().to_string();
        let key_id = public.key_id().to_string();
        let public_key = public.public_key_bytes().as_slice();
        let fingerprint = public.fingerprint();
        let fingerprint = fingerprint.as_slice();

        let result = transaction.execute(
            "INSERT INTO service_instances \
             (instance_id, service_id, endpoint, registered_at, \
              lease_expires_at, lease_revision) \
             VALUES ($1::text::uuid, $2::text::uuid, $3, $4, $5, $6)",
            &[
                &instance_id,
                &service_id,
                &instance.endpoint(),
                &instance.registered_at(),
                &instance.lease_expires_at(),
                &instance.lease_revision(),
            ],
        );
        match result {
            Ok(1) => {}
            Ok(rows) => {
                return Err(InstanceRegistryError::Repository(format!(
                    "instance insert changed {rows} rows"
                )));
            }
            Err(error) if is_unique_violation(&error) => {
                return Err(InstanceRegistryError::AlreadyExists(public.instance_id()));
            }
            Err(error) if is_foreign_key_violation(&error) => {
                return Err(InstanceRegistryError::UnknownService(public.service_id()));
            }
            Err(error) => return Err(repository_error(error)),
        }

        transaction
            .execute(
                "INSERT INTO service_instance_keys \
                 (key_id, instance_id, algorithm, public_key, fingerprint, valid_from) \
                 VALUES ($1::text::uuid, $2::text::uuid, $3, $4, $5, $6)",
                &[
                    &key_id,
                    &instance_id,
                    &public.algorithm(),
                    &public_key,
                    &fingerprint,
                    &instance.registered_at(),
                ],
            )
            .map_err(|error| {
                if is_unique_violation(&error) {
                    InstanceRegistryError::AlreadyExists(public.instance_id())
                } else {
                    repository_error(error)
                }
            })?;

        append_audit(
            &mut transaction,
            &instance,
            "registered",
            instance.registered_at(),
        )?;
        transaction.commit().map_err(repository_error)
    }

    fn find(
        &self,
        instance_id: InstanceId,
    ) -> Result<Option<RegisteredInstance>, InstanceRegistryError> {
        let mut connection = self.database.connection().map_err(repository_error)?;
        let instance_id = instance_id.to_string();
        connection
            .query_opt(FIND_INSTANCE_SQL, &[&instance_id])
            .map_err(repository_error)?
            .as_ref()
            .map(instance_from_row)
            .transpose()
    }

    fn renew(
        &self,
        instance_id: InstanceId,
        expected_revision: i64,
        renewed_at: i64,
        lease_expires_at: i64,
    ) -> Result<RegisteredInstance, InstanceRegistryError> {
        if renewed_at < 0 || lease_expires_at <= renewed_at || expected_revision <= 0 {
            return Err(InstanceRegistryError::InvalidTimestamp);
        }

        let mut connection = self.database.connection().map_err(repository_error)?;
        let mut transaction = connection.transaction().map_err(repository_error)?;
        let id = instance_id.to_string();
        let rows = transaction
            .execute(
                "UPDATE service_instances \
                 SET lease_expires_at = $4, lease_revision = lease_revision + 1 \
                 WHERE instance_id = $1::text::uuid \
                   AND lease_revision = $2 AND lease_expires_at > $3 \
                   AND registered_at <= $3 AND revoked_at IS NULL",
                &[&id, &expected_revision, &renewed_at, &lease_expires_at],
            )
            .map_err(repository_error)?;

        if rows == 0 {
            return Err(classify_failed_renewal(
                &mut transaction,
                instance_id,
                expected_revision,
                renewed_at,
            )?);
        }
        if rows != 1 {
            return Err(InstanceRegistryError::Repository(format!(
                "lease renewal changed {rows} rows"
            )));
        }

        let row = transaction
            .query_one(FIND_INSTANCE_SQL, &[&id])
            .map_err(repository_error)?;
        let renewed = instance_from_row(&row)?;
        append_audit(&mut transaction, &renewed, "renewed", renewed_at)?;
        transaction.commit().map_err(repository_error)?;
        Ok(renewed)
    }

    fn revoke(
        &self,
        instance_id: InstanceId,
        revoked_at: i64,
    ) -> Result<RegisteredInstance, InstanceRegistryError> {
        if revoked_at < 0 {
            return Err(InstanceRegistryError::InvalidTimestamp);
        }

        let mut connection = self.database.connection().map_err(repository_error)?;
        let mut transaction = connection.transaction().map_err(repository_error)?;
        let id = instance_id.to_string();
        let rows = transaction
            .execute(
                "UPDATE service_instances SET revoked_at = $2 \
                 WHERE instance_id = $1::text::uuid \
                   AND registered_at <= $2 AND revoked_at IS NULL",
                &[&id, &revoked_at],
            )
            .map_err(repository_error)?;
        match rows {
            1 => {}
            0 => {
                let existing = transaction
                    .query_opt(
                        "SELECT registered_at, revoked_at FROM service_instances \
                         WHERE instance_id = $1::text::uuid",
                        &[&id],
                    )
                    .map_err(repository_error)?;
                return Err(match existing {
                    None => InstanceRegistryError::NotFound(instance_id),
                    Some(row) if row.get::<_, i64>("registered_at") > revoked_at => {
                        InstanceRegistryError::InvalidTimestamp
                    }
                    Some(_) => InstanceRegistryError::Revoked(instance_id),
                });
            }
            rows => {
                return Err(InstanceRegistryError::Repository(format!(
                    "instance revocation changed {rows} rows"
                )));
            }
        }

        let key_rows = transaction
            .execute(
                "UPDATE service_instance_keys SET revoked_at = $2 \
                 WHERE instance_id = $1::text::uuid AND revoked_at IS NULL",
                &[&id, &revoked_at],
            )
            .map_err(repository_error)?;
        if key_rows != 1 {
            return Err(InstanceRegistryError::Repository(format!(
                "instance key revocation changed {key_rows} rows"
            )));
        }
        let row = transaction
            .query_one(FIND_INSTANCE_SQL, &[&id])
            .map_err(repository_error)?;
        let revoked = instance_from_row(&row)?;
        append_audit(&mut transaction, &revoked, "revoked", revoked_at)?;
        transaction.commit().map_err(repository_error)?;
        Ok(revoked)
    }
}

fn append_audit(
    transaction: &mut r2d2_postgres::postgres::Transaction<'_>,
    instance: &RegisteredInstance,
    action: &str,
    recorded_at: i64,
) -> Result<(), InstanceRegistryError> {
    let public = instance.public_key();
    transaction
        .execute(
            "INSERT INTO service_instance_registry_audit \
             (service_id, instance_id, key_id, action, lease_revision, recorded_at) \
             VALUES ($1::text::uuid, $2::text::uuid, $3::text::uuid, $4, $5, $6)",
            &[
                &public.service_id().to_string(),
                &public.instance_id().to_string(),
                &public.key_id().to_string(),
                &action,
                &instance.lease_revision(),
                &recorded_at,
            ],
        )
        .map_err(repository_error)?;
    Ok(())
}

fn classify_failed_renewal(
    transaction: &mut r2d2_postgres::postgres::Transaction<'_>,
    instance_id: InstanceId,
    expected_revision: i64,
    renewed_at: i64,
) -> Result<InstanceRegistryError, InstanceRegistryError> {
    let id = instance_id.to_string();
    let row = transaction
        .query_opt(
            "SELECT registered_at, lease_revision, lease_expires_at, revoked_at \
             FROM service_instances WHERE instance_id = $1::text::uuid",
            &[&id],
        )
        .map_err(repository_error)?;
    Ok(match row {
        None => InstanceRegistryError::NotFound(instance_id),
        Some(row) if row.get::<_, Option<i64>>("revoked_at").is_some() => {
            InstanceRegistryError::Revoked(instance_id)
        }
        Some(row) if row.get::<_, i64>("registered_at") > renewed_at => {
            InstanceRegistryError::InvalidTimestamp
        }
        Some(row) if row.get::<_, i64>("lease_expires_at") <= renewed_at => {
            InstanceRegistryError::Expired(instance_id)
        }
        Some(row) if row.get::<_, i64>("lease_revision") != expected_revision => {
            InstanceRegistryError::RevisionConflict(instance_id)
        }
        Some(_) => InstanceRegistryError::Repository("lease renewal was not applied".to_owned()),
    })
}

fn instance_from_row(row: &Row) -> Result<RegisteredInstance, InstanceRegistryError> {
    let service_id = row
        .get::<_, String>("service_id")
        .parse::<ActorId>()
        .map_err(|error| {
            InstanceRegistryError::Repository(format!("invalid stored service ID: {error}"))
        })?;
    let instance_id = row.get::<_, String>("instance_id").parse::<InstanceId>()?;
    let key_id = row.get::<_, String>("key_id").parse::<KeyId>()?;
    let bytes = row.get::<_, Vec<u8>>("public_key");
    let public_key: [u8; PUBLIC_KEY_LENGTH] = bytes
        .try_into()
        .map_err(|_| InstanceRegistryError::InvalidStoredRecord)?;
    let public_key = InstancePublicKey::restore(service_id, instance_id, key_id, public_key)?;

    RegisteredInstance::restore(
        public_key,
        &row.get::<_, String>("endpoint"),
        row.get("registered_at"),
        row.get("lease_expires_at"),
        row.get("lease_revision"),
        row.get("revoked_at"),
    )
}

fn is_unique_violation(error: &PostgresError) -> bool {
    has_sql_state(error, &SqlState::UNIQUE_VIOLATION)
}

fn is_foreign_key_violation(error: &PostgresError) -> bool {
    has_sql_state(error, &SqlState::FOREIGN_KEY_VIOLATION)
}

fn has_sql_state(error: &PostgresError, state: &SqlState) -> bool {
    error
        .as_db_error()
        .is_some_and(|database_error| database_error.code() == state)
}

fn repository_error(error: impl std::fmt::Display) -> InstanceRegistryError {
    InstanceRegistryError::Repository(error.to_string())
}
