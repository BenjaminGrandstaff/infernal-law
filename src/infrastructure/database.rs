//! Goal: own internal PostgreSQL wiring, readiness, and pgvector verification
//! without exposing a caller-supplied SQL command surface.

use std::env;
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::time::Duration;

use r2d2_postgres::PostgresConnectionManager;
use r2d2_postgres::postgres::{Config as PostgresConfig, Error as PostgresError, NoTls};
use r2d2_postgres::r2d2::{self, Pool, PooledConnection};

const DATABASE_URL_ENV: &str = "DATABASE_URL";
const DEFAULT_MAX_POOL_SIZE: u32 = 10;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

type PostgresPool = Pool<PostgresConnectionManager<NoTls>>;
pub(super) type PostgresConnection = PooledConnection<PostgresConnectionManager<NoTls>>;

#[derive(Clone)]
pub struct DatabaseConfig {
    url: String,
    max_pool_size: u32,
}

impl DatabaseConfig {
    pub fn new(url: impl Into<String>) -> Result<Self, DatabaseError> {
        let url = url.into();
        if url.trim().is_empty() {
            return Err(DatabaseError::EmptyUrl);
        }

        Ok(Self {
            url,
            max_pool_size: DEFAULT_MAX_POOL_SIZE,
        })
    }

    pub fn from_env() -> Result<Self, DatabaseError> {
        let url = env::var(DATABASE_URL_ENV)
            .map_err(|_| DatabaseError::MissingEnvironment(DATABASE_URL_ENV))?;
        Self::new(url)
    }

    pub fn with_max_pool_size(mut self, max_pool_size: u32) -> Result<Self, DatabaseError> {
        if max_pool_size == 0 {
            return Err(DatabaseError::InvalidPoolSize);
        }

        self.max_pool_size = max_pool_size;
        Ok(self)
    }
}

#[derive(Clone)]
pub struct Database {
    pool: PostgresPool,
}

impl Database {
    pub fn connect(config: &DatabaseConfig) -> Result<Self, DatabaseError> {
        let mut postgres_config: PostgresConfig = config
            .url
            .parse()
            .map_err(DatabaseError::InvalidPostgresConfig)?;
        postgres_config.connect_timeout(CONNECT_TIMEOUT);
        let manager = PostgresConnectionManager::new(postgres_config, NoTls);
        let pool = Pool::builder()
            .max_size(config.max_pool_size)
            .min_idle(Some(1))
            .build(manager)
            .map_err(DatabaseError::Pool)?;
        let database = Self { pool };

        database.check_connection()?;
        database.require_vector_extension()?;
        Ok(database)
    }

    pub fn connect_from_env() -> Result<Self, DatabaseError> {
        Self::connect(&DatabaseConfig::from_env()?)
    }

    pub fn check_connection(&self) -> Result<(), DatabaseError> {
        let mut connection = self.pool.get().map_err(DatabaseError::Pool)?;
        connection
            .simple_query("SELECT 1")
            .map_err(DatabaseError::Query)?;
        Ok(())
    }

    pub fn vector_extension_version(&self) -> Result<String, DatabaseError> {
        let mut connection = self.connection()?;
        let row = connection
            .query_opt(
                "SELECT extversion FROM pg_extension WHERE extname = 'vector'",
                &[],
            )
            .map_err(DatabaseError::Query)?
            .ok_or(DatabaseError::VectorExtensionMissing)?;

        Ok(row.get("extversion"))
    }

    fn require_vector_extension(&self) -> Result<(), DatabaseError> {
        self.vector_extension_version().map(|_| ())
    }

    pub fn migrate(&self) -> Result<(), DatabaseError> {
        let mut connection = self.connection()?;
        connection
            .batch_execute(concat!(
                include_str!("../../migrations/0001_identities.sql"),
                "\n",
                include_str!("../../migrations/0002_instance_public_key_registry.sql"),
                "\n",
                include_str!("../../migrations/0003_service_enrollment_bindings.sql"),
                "\n",
                include_str!("../../migrations/0004_subscriptions.sql"),
                "\n",
                include_str!("../../migrations/0005_instance_handshakes.sql"),
                "\n",
                include_str!("../../migrations/0006_service_request_replay_protection.sql"),
                "\n",
                include_str!("../../migrations/0007_communication_admission.sql"),
                "\n",
                include_str!("../../migrations/0008_requests.sql"),
                "\n",
                include_str!("../../migrations/0009_authority_grants.sql"),
                "\n",
                include_str!("../../migrations/0010_authority_schema_versions.sql")
            ))
            .map_err(DatabaseError::Query)
    }

    pub(super) fn connection(&self) -> Result<PostgresConnection, DatabaseError> {
        self.pool.get().map_err(DatabaseError::Pool)
    }
}

#[derive(Debug)]
pub enum DatabaseError {
    EmptyUrl,
    InvalidPoolSize,
    InvalidPostgresConfig(PostgresError),
    MissingEnvironment(&'static str),
    Pool(r2d2::Error),
    Query(PostgresError),
    VectorExtensionMissing,
}

impl Display for DatabaseError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyUrl => formatter.write_str("database URL cannot be empty"),
            Self::InvalidPoolSize => formatter.write_str("database pool size must be positive"),
            Self::InvalidPostgresConfig(error) => {
                write!(formatter, "invalid PostgreSQL configuration: {error}")
            }
            Self::MissingEnvironment(name) => {
                write!(formatter, "required environment variable {name} is not set")
            }
            Self::Pool(error) => write!(formatter, "database pool error: {error}"),
            Self::Query(error) => write!(formatter, "database query failed: {error}"),
            Self::VectorExtensionMissing => {
                formatter.write_str("required PostgreSQL extension 'vector' is not installed")
            }
        }
    }
}

impl Error for DatabaseError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidPostgresConfig(error) | Self::Query(error) => Some(error),
            Self::Pool(error) => Some(error),
            Self::EmptyUrl
            | Self::InvalidPoolSize
            | Self::MissingEnvironment(_)
            | Self::VectorExtensionMissing => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{DatabaseConfig, DatabaseError};

    #[test]
    fn rejects_an_empty_database_url() {
        assert!(matches!(
            DatabaseConfig::new("  "),
            Err(DatabaseError::EmptyUrl)
        ));
    }

    #[test]
    fn rejects_a_zero_sized_pool() {
        let result = DatabaseConfig::new("postgres://localhost/example")
            .unwrap()
            .with_max_pool_size(0);

        assert!(matches!(result, Err(DatabaseError::InvalidPoolSize)));
    }

    #[test]
    fn accepts_explicit_connection_configuration() {
        let config = DatabaseConfig::new("postgres://localhost/example")
            .unwrap()
            .with_max_pool_size(4);

        assert!(config.is_ok());
    }
}
