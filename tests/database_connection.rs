//! Goal: verify the PostgreSQL wiring and pgvector requirement against a real
//! database independently of the HTTP server.

use infernal_law::infrastructure::database::Database;

#[test]
#[ignore = "requires DATABASE_URL and a running PostgreSQL instance with pgvector"]
fn connects_and_finds_vector_extension() {
    let database = Database::connect_from_env().expect("database should connect");

    database
        .check_connection()
        .expect("database should answer a readiness query");
    assert!(!database.vector_extension_version().unwrap().is_empty());
}
