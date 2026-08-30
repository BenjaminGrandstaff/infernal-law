//! Goal: prove ILK-003 route materialization is idempotent, keyed by
//! (request_id, subscription_id), and append-only in live PostgreSQL.

use std::env;

use infernal_law::infrastructure::postgres_authority_repository::PostgresAuthorityRepository;
use infernal_law::kernel::authority::{
    ContentDigest, SchemaKind, SchemaName, SchemaRepository, SchemaVersionRefs, Scope,
};
use infernal_law::kernel::identity::{ActorId, ActorKind};
use infernal_law::kernel::requests::Request;
use infernal_law::kernel::subscriptions::{DeliveryMode, EventType};
use infernal_law::wiring::Application;
use r2d2_postgres::postgres::{Client, NoTls};

fn publish_schema_versions(
    application: &Application,
    owner: ActorId,
    name: &str,
    discriminant: u8,
) -> SchemaVersionRefs {
    let repository = PostgresAuthorityRepository::new(application.database().clone());
    let name = SchemaName::new(name).unwrap();
    let artifact = repository
        .publish(
            SchemaKind::Artifact,
            name.clone(),
            owner,
            ContentDigest::from_bytes([discriminant; 32]),
            1,
        )
        .unwrap();
    let permission_policy = repository
        .publish(
            SchemaKind::PermissionPolicy,
            name,
            owner,
            ContentDigest::from_bytes([discriminant; 32]),
            1,
        )
        .unwrap();
    SchemaVersionRefs::new(artifact.version().id(), permission_policy.version().id())
}

#[test]
#[ignore = "requires DATABASE_URL, INFERNAL_LAW_SERVICE_ID, and PostgreSQL with pgvector"]
fn route_materialization_is_idempotent_and_survives_reconnection() {
    let first_process = Application::from_env().expect("application should connect and migrate");
    let source = first_process
        .identities()
        .create(ActorKind::Service, "Route persistence integration source")
        .unwrap();
    let destination = first_process
        .identities()
        .create(
            ActorKind::Service,
            "Route persistence integration destination",
        )
        .unwrap();
    let event_type = EventType::new("test.route-materialization.v1").unwrap();
    let subscription = first_process
        .subscriptions()
        .create(destination.id(), event_type, DeliveryMode::Inclusive, 1)
        .unwrap();

    let schema_versions = publish_schema_versions(
        &first_process,
        source.id(),
        "test.route-materialization",
        31,
    );
    let request = Request::create(
        source.id(),
        "test.route-materialization.v1",
        Scope::wildcard(),
        schema_versions,
    )
    .unwrap();
    let fingerprint = request.fingerprint();
    let accepted = first_process
        .requests()
        .accept(request, fingerprint)
        .unwrap();
    let request_id = accepted.record().request().id();

    let first_route = first_process
        .routes()
        .materialize(
            source.id(),
            request_id,
            subscription.id(),
            destination.id(),
            10,
        )
        .unwrap();

    let second_process = Application::from_env().expect("application should reconnect");
    let repeated_route = second_process
        .routes()
        .materialize(
            source.id(),
            request_id,
            subscription.id(),
            destination.id(),
            20,
        )
        .unwrap();
    assert_eq!(first_route.id(), repeated_route.id());
    assert_eq!(
        repeated_route.created_at(),
        10,
        "the first materialization wins, not the retry"
    );

    let listed = second_process
        .routes()
        .list_for_request(request_id)
        .unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].destination_service(), destination.id());

    let by_destination = second_process
        .routes()
        .list_for_destination(destination.id())
        .unwrap();
    assert_eq!(by_destination, vec![first_route.clone()]);

    assert_database_guards(request_id, first_route.id());
}

fn assert_database_guards(
    request_id: infernal_law::kernel::requests::RequestId,
    route_id: infernal_law::kernel::requests::RouteId,
) {
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be present");
    let mut client = Client::connect(&database_url, NoTls).expect("test database should connect");
    let row_count: i64 = client
        .query_one(
            "SELECT count(*) FROM request_routes WHERE request_id = $1::text::uuid",
            &[&request_id.to_string()],
        )
        .unwrap()
        .get(0);
    assert_eq!(row_count, 1, "materializing twice must not duplicate rows");

    assert!(
        client
            .execute(
                "DELETE FROM request_routes WHERE route_id = $1::text::uuid",
                &[&route_id.to_string()],
            )
            .is_err(),
        "request routes must be append-only"
    );
    assert!(
        client
            .execute(
                "UPDATE request_routes SET destination_service_id = destination_service_id \
                 WHERE route_id = $1::text::uuid",
                &[&route_id.to_string()],
            )
            .is_err(),
        "request routes must be immutable"
    );
}
