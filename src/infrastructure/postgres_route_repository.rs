//! Goal: idempotently persist ILK-003 request routes with fixed,
//! parameterized SQL -- materializing the same `(request_id,
//! subscription_id)` pair twice returns the existing route rather than
//! creating a second one, so repeated matching scans and retries are safe.

use r2d2_postgres::postgres::{Error as PostgresError, Row, error::SqlState};

use crate::kernel::identity::ActorId;
use crate::kernel::requests::{RequestError, RequestId, Route, RouteId, RouteRepository};
use crate::kernel::subscriptions::SubscriptionId;

use super::database::Database;

const INSERT_SQL: &str = "INSERT INTO request_routes \
    (route_id, source_service_id, request_id, subscription_id, destination_service_id, \
     created_at) \
    VALUES ($1::text::uuid, $2::text::uuid, $3::text::uuid, $4::text::uuid, $5::text::uuid, $6) \
    ON CONFLICT (request_id, subscription_id) DO NOTHING \
    RETURNING route_id::text, source_service_id::text, request_id::text, \
              subscription_id::text, destination_service_id::text, created_at";
const FIND_BY_MATCH_KEY_SQL: &str = "SELECT route_id::text, source_service_id::text, \
        request_id::text, subscription_id::text, destination_service_id::text, created_at \
    FROM request_routes \
    WHERE request_id = $1::text::uuid AND subscription_id = $2::text::uuid";
const LIST_FOR_REQUEST_SQL: &str = "SELECT route_id::text, source_service_id::text, \
        request_id::text, subscription_id::text, destination_service_id::text, created_at \
    FROM request_routes \
    WHERE request_id = $1::text::uuid ORDER BY created_at, route_id";

#[derive(Clone)]
pub struct PostgresRouteRepository {
    database: Database,
}

impl PostgresRouteRepository {
    pub const fn new(database: Database) -> Self {
        Self { database }
    }
}

impl RouteRepository for PostgresRouteRepository {
    fn materialize(&self, route: Route) -> Result<Route, RequestError> {
        let mut connection = self.database.connection().map_err(repository_error)?;
        let route_id = route.id().to_string();
        let source_service = route.source_service().to_string();
        let request_id = route.request_id().to_string();
        let subscription_id = route.subscription_id().to_string();
        let destination_service = route.destination_service().to_string();

        let inserted = connection.query_opt(
            INSERT_SQL,
            &[
                &route_id,
                &source_service,
                &request_id,
                &subscription_id,
                &destination_service,
                &route.created_at(),
            ],
        );
        let inserted = match inserted {
            Ok(value) => value,
            Err(error) => {
                return Err(
                    foreign_key_violation_error(&error).unwrap_or_else(|| repository_error(error))
                );
            }
        };
        if let Some(row) = inserted {
            return route_from_row(&row);
        }

        let existing = connection
            .query_opt(FIND_BY_MATCH_KEY_SQL, &[&request_id, &subscription_id])
            .map_err(repository_error)?
            .ok_or_else(|| {
                RequestError::Repository(
                    "conflicting route disappeared during materialization".to_owned(),
                )
            })?;
        route_from_row(&existing)
    }

    fn list_for_request(&self, request_id: RequestId) -> Result<Vec<Route>, RequestError> {
        let mut connection = self.database.connection().map_err(repository_error)?;
        connection
            .query(LIST_FOR_REQUEST_SQL, &[&request_id.to_string()])
            .map_err(repository_error)?
            .iter()
            .map(route_from_row)
            .collect()
    }
}

fn route_from_row(row: &Row) -> Result<Route, RequestError> {
    let id = row.get::<_, String>("route_id").parse::<RouteId>()?;
    let source_service = parse_actor_id(row, "source_service_id")?;
    let request_id = row.get::<_, String>("request_id").parse::<RequestId>()?;
    let subscription_id = row
        .get::<_, String>("subscription_id")
        .parse::<SubscriptionId>()
        .map_err(|_| {
            RequestError::Repository("stored route subscription ID is invalid".to_owned())
        })?;
    let destination_service = parse_actor_id(row, "destination_service_id")?;
    Route::restore(
        id,
        source_service,
        request_id,
        subscription_id,
        destination_service,
        row.get("created_at"),
    )
    .map_err(|_| RequestError::Repository("stored route is invalid".to_owned()))
}

fn parse_actor_id(row: &Row, column: &str) -> Result<ActorId, RequestError> {
    row.get::<_, String>(column)
        .parse::<ActorId>()
        .map_err(|error| RequestError::Repository(format!("invalid stored {column}: {error}")))
}

/// Maps an INSERT's foreign-key violation to the specific reference that
/// failed -- `request_routes` foreign-keys three different things
/// (subscription, destination identity, and the accepted request itself),
/// and conflating them would misreport which one was actually missing.
fn foreign_key_violation_error(error: &PostgresError) -> Option<RequestError> {
    let db_error = error.as_db_error()?;
    if db_error.code() != &SqlState::FOREIGN_KEY_VIOLATION {
        return None;
    }
    match db_error.constraint() {
        Some("request_routes_subscription_id_fkey") => Some(RequestError::UnknownSubscription),
        Some(
            "request_routes_accepted_request_fk" | "request_routes_destination_service_id_fkey",
        ) => Some(RequestError::Repository(
            "route references an unknown request or destination identity".to_owned(),
        )),
        _ => None,
    }
}

fn repository_error(error: impl std::fmt::Display) -> RequestError {
    RequestError::Repository(error.to_string())
}
