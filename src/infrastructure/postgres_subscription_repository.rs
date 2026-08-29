//! Goal: persist ILK-010 subscriptions with fixed, parameterized SQL and
//! atomic append-only audit records while exposing no SQL command surface.

use r2d2_postgres::postgres::{Error as PostgresError, Row, Transaction, error::SqlState};

use crate::kernel::identity::ActorId;
use crate::kernel::subscriptions::{
    EventType, Subscription, SubscriptionError, SubscriptionId, SubscriptionRepository,
};

use super::database::Database;

const LIST_HISTORY_SQL: &str = "SELECT id::text, service_id::text, event_type, \
        created_at, disabled_at FROM subscriptions \
    WHERE service_id = $1::text::uuid ORDER BY created_at, id";
const LIST_ACTIVE_SQL: &str = "SELECT id::text, service_id::text, event_type, \
        created_at, disabled_at FROM subscriptions \
    WHERE service_id = $1::text::uuid AND disabled_at IS NULL \
    ORDER BY created_at, id";
const DISABLE_SQL: &str = "UPDATE subscriptions SET disabled_at = $3 \
    WHERE id = $1::text::uuid AND service_id = $2::text::uuid \
      AND disabled_at IS NULL AND created_at <= $3 \
    RETURNING id::text, service_id::text, event_type, created_at, disabled_at";

#[derive(Clone)]
pub struct PostgresSubscriptionRepository {
    database: Database,
}

impl PostgresSubscriptionRepository {
    pub const fn new(database: Database) -> Self {
        Self { database }
    }
}

impl SubscriptionRepository for PostgresSubscriptionRepository {
    fn insert(&self, subscription: Subscription) -> Result<(), SubscriptionError> {
        let mut connection = self.database.connection().map_err(repository_error)?;
        let mut transaction = connection.transaction().map_err(repository_error)?;
        let id = subscription.id().to_string();
        let service_id = subscription.service_id().to_string();
        let event_type = subscription.event_type().as_str();
        let result = transaction.execute(
            "INSERT INTO subscriptions \
             (id, service_id, event_type, created_at) \
             VALUES ($1::text::uuid, $2::text::uuid, $3, $4)",
            &[&id, &service_id, &event_type, &subscription.created_at()],
        );
        match result {
            Ok(1) => {}
            Ok(rows) => {
                return Err(SubscriptionError::Repository(format!(
                    "subscription insert changed {rows} rows"
                )));
            }
            Err(error) if is_unique_violation(&error) => {
                return Err(if constraint(&error) == Some("subscriptions_pkey") {
                    SubscriptionError::AlreadyExists(subscription.id())
                } else {
                    SubscriptionError::DuplicateActive(
                        subscription.service_id(),
                        subscription.event_type().clone(),
                    )
                });
            }
            Err(error) if is_foreign_key_violation(&error) => {
                return Err(SubscriptionError::UnknownService(subscription.service_id()));
            }
            Err(error) => return Err(repository_error(error)),
        }
        append_audit(
            &mut transaction,
            &subscription,
            "created",
            subscription.created_at(),
        )?;
        transaction.commit().map_err(repository_error)
    }

    fn list_for_service(
        &self,
        service_id: ActorId,
    ) -> Result<Vec<Subscription>, SubscriptionError> {
        list(&self.database, service_id, false)
    }

    fn list_active_for_service(
        &self,
        service_id: ActorId,
    ) -> Result<Vec<Subscription>, SubscriptionError> {
        list(&self.database, service_id, true)
    }

    fn disable(
        &self,
        service_id: ActorId,
        subscription_id: SubscriptionId,
        disabled_at: i64,
    ) -> Result<Subscription, SubscriptionError> {
        if disabled_at < 0 {
            return Err(SubscriptionError::InvalidTimestamp);
        }
        let mut connection = self.database.connection().map_err(repository_error)?;
        let mut transaction = connection.transaction().map_err(repository_error)?;
        let id = subscription_id.to_string();
        let owner = service_id.to_string();
        let row = transaction
            .query_opt(DISABLE_SQL, &[&id, &owner, &disabled_at])
            .map_err(repository_error)?;
        let subscription = match row {
            Some(row) => subscription_from_row(&row)?,
            None => {
                return Err(classify_failed_disable(
                    &mut transaction,
                    service_id,
                    subscription_id,
                    disabled_at,
                )?);
            }
        };
        append_audit(&mut transaction, &subscription, "disabled", disabled_at)?;
        transaction.commit().map_err(repository_error)?;
        Ok(subscription)
    }
}

fn list(
    database: &Database,
    service_id: ActorId,
    active_only: bool,
) -> Result<Vec<Subscription>, SubscriptionError> {
    let mut connection = database.connection().map_err(repository_error)?;
    let sql = if active_only {
        LIST_ACTIVE_SQL
    } else {
        LIST_HISTORY_SQL
    };
    connection
        .query(sql, &[&service_id.to_string()])
        .map_err(repository_error)?
        .iter()
        .map(subscription_from_row)
        .collect()
}

fn classify_failed_disable(
    transaction: &mut Transaction<'_>,
    service_id: ActorId,
    subscription_id: SubscriptionId,
    disabled_at: i64,
) -> Result<SubscriptionError, SubscriptionError> {
    let row = transaction
        .query_opt(
            "SELECT service_id::text, created_at, disabled_at FROM subscriptions \
             WHERE id = $1::text::uuid",
            &[&subscription_id.to_string()],
        )
        .map_err(repository_error)?;
    Ok(match row {
        None => SubscriptionError::NotFound(subscription_id),
        Some(row)
            if row
                .get::<_, String>("service_id")
                .parse::<ActorId>()
                .map_err(|error| {
                    SubscriptionError::Repository(format!("invalid stored service ID: {error}"))
                })?
                != service_id =>
        {
            SubscriptionError::NotFound(subscription_id)
        }
        Some(row) if row.get::<_, Option<i64>>("disabled_at").is_some() => {
            SubscriptionError::AlreadyDisabled(subscription_id)
        }
        Some(row) if row.get::<_, i64>("created_at") > disabled_at => {
            SubscriptionError::InvalidTimestamp
        }
        Some(_) => SubscriptionError::Repository("subscription disable was not applied".to_owned()),
    })
}

fn append_audit(
    transaction: &mut Transaction<'_>,
    subscription: &Subscription,
    action: &str,
    recorded_at: i64,
) -> Result<(), SubscriptionError> {
    transaction
        .execute(
            "INSERT INTO subscription_audit \
             (subscription_id, service_id, event_type, action, recorded_at) \
             VALUES ($1::text::uuid, $2::text::uuid, $3, $4, $5)",
            &[
                &subscription.id().to_string(),
                &subscription.service_id().to_string(),
                &subscription.event_type().as_str(),
                &action,
                &recorded_at,
            ],
        )
        .map_err(repository_error)?;
    Ok(())
}

fn subscription_from_row(row: &Row) -> Result<Subscription, SubscriptionError> {
    let id = row.get::<_, String>("id").parse::<SubscriptionId>()?;
    let service_id = row
        .get::<_, String>("service_id")
        .parse::<ActorId>()
        .map_err(|error| {
            SubscriptionError::Repository(format!("invalid stored service ID: {error}"))
        })?;
    let event_type = row.get::<_, String>("event_type").parse::<EventType>()?;
    Subscription::restore(
        id,
        service_id,
        event_type,
        row.get("created_at"),
        row.get("disabled_at"),
    )
    .map_err(|_| SubscriptionError::Repository("stored subscription is invalid".to_owned()))
}

fn is_unique_violation(error: &PostgresError) -> bool {
    error
        .as_db_error()
        .is_some_and(|error| error.code() == &SqlState::UNIQUE_VIOLATION)
}

fn constraint(error: &PostgresError) -> Option<&str> {
    error.as_db_error().and_then(|error| error.constraint())
}

fn is_foreign_key_violation(error: &PostgresError) -> bool {
    error
        .as_db_error()
        .is_some_and(|error| error.code() == &SqlState::FOREIGN_KEY_VIOLATION)
}

fn repository_error(error: impl std::fmt::Display) -> SubscriptionError {
    SubscriptionError::Repository(error.to_string())
}
