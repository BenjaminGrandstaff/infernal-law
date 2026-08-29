//! Goal: project distinct eligible instances for stable services that have at
//! least one active subscription, using one fixed read-only SQL query.

use r2d2_postgres::postgres::Row;

use crate::kernel::handshakes::{HandshakeError, SubscribedInstanceDiscovery};
use crate::kernel::identity::ActorId;
use crate::kernel::instance_keys::{InstanceId, InstancePublicKey, KeyId, PUBLIC_KEY_LENGTH};
use crate::kernel::instance_registry::RegisteredInstance;

use super::database::Database;

#[derive(Clone)]
pub struct PostgresSubscribedInstanceDiscovery {
    database: Database,
}

impl PostgresSubscribedInstanceDiscovery {
    pub const fn new(database: Database) -> Self {
        Self { database }
    }
}

impl SubscribedInstanceDiscovery for PostgresSubscribedInstanceDiscovery {
    fn eligible_subscribed_instances(
        &self,
        now: i64,
    ) -> Result<Vec<RegisteredInstance>, HandshakeError> {
        if now < 0 {
            return Err(HandshakeError::InvalidTimestamp);
        }
        let mut connection = self.database.connection().map_err(repository_error)?;
        connection
            .query(
                "SELECT DISTINCT si.instance_id::text, si.service_id::text, si.endpoint, \
                    si.registered_at, si.lease_expires_at, si.lease_revision, si.revoked_at, \
                    sik.key_id::text, sik.public_key \
             FROM subscriptions s \
             JOIN service_instances si ON si.service_id = s.service_id \
             JOIN service_instance_keys sik ON sik.instance_id = si.instance_id \
             WHERE s.disabled_at IS NULL AND si.revoked_at IS NULL \
               AND si.registered_at <= $1 AND si.lease_expires_at > $1 \
               AND sik.revoked_at IS NULL \
             ORDER BY si.instance_id::text",
                &[&now],
            )
            .map_err(repository_error)?
            .iter()
            .map(instance_from_row)
            .collect()
    }
}

fn instance_from_row(row: &Row) -> Result<RegisteredInstance, HandshakeError> {
    let service_id = row
        .get::<_, String>("service_id")
        .parse::<ActorId>()
        .map_err(|_| HandshakeError::InvalidStoredRecord)?;
    let instance_id = row
        .get::<_, String>("instance_id")
        .parse::<InstanceId>()
        .map_err(|_| HandshakeError::InvalidStoredRecord)?;
    let key_id = row
        .get::<_, String>("key_id")
        .parse::<KeyId>()
        .map_err(|_| HandshakeError::InvalidStoredRecord)?;
    let bytes: [u8; PUBLIC_KEY_LENGTH] = row
        .get::<_, Vec<u8>>("public_key")
        .try_into()
        .map_err(|_| HandshakeError::InvalidStoredRecord)?;
    let public_key = InstancePublicKey::restore(service_id, instance_id, key_id, bytes)
        .map_err(|_| HandshakeError::InvalidStoredRecord)?;
    RegisteredInstance::restore(
        public_key,
        &row.get::<_, String>("endpoint"),
        row.get("registered_at"),
        row.get("lease_expires_at"),
        row.get("lease_revision"),
        row.get("revoked_at"),
    )
    .map_err(|_| HandshakeError::InvalidStoredRecord)
}

fn repository_error(error: impl std::fmt::Display) -> HandshakeError {
    HandshakeError::Repository(error.to_string())
}
