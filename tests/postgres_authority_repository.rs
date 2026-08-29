//! Goal: prove authority grants are administered only through the
//! out-of-band, idempotent, conflict-detecting database function, are
//! immutable and append-only, and that `PostgresAuthorityRepository` reads
//! exactly the grants matching a given fact bundle's decision point.

use std::env;

use infernal_law::infrastructure::postgres_authority_repository::PostgresAuthorityRepository;
use infernal_law::kernel::authority::{AuthorityRepository, PolicyFacts, Scope};
use infernal_law::kernel::identity::ActorKind;
use infernal_law::kernel::requests::ActionName;
use infernal_law::wiring::Application;
use r2d2_postgres::postgres::{Client, NoTls, Row};
use uuid::Uuid;

#[test]
#[ignore = "requires DATABASE_URL, INFERNAL_LAW_SERVICE_ID, and PostgreSQL with pgvector"]
fn authority_grants_are_administered_out_of_band_and_read_by_matching_facts() {
    let application = Application::from_env().expect("application should connect and migrate");
    let source = application
        .identities()
        .create(ActorKind::Service, "Authority grant integration source")
        .unwrap();
    let destination = application
        .identities()
        .create(
            ActorKind::Service,
            "Authority grant integration destination",
        )
        .unwrap();
    let repository = PostgresAuthorityRepository::new(application.database().clone());

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be present");
    let mut administrator =
        Client::connect(&database_url, NoTls).expect("test database should connect");

    let grant_id = Uuid::new_v4();
    let correlation_id = Uuid::new_v4();
    create_grant(
        &mut administrator,
        grant_id,
        source.id().to_string(),
        "billing.invoice.submit",
        "*",
        None,
        0,
        None,
        correlation_id,
        1_000,
    );

    let facts = PolicyFacts::for_request_acceptance(
        source.id(),
        action("billing.invoice.submit"),
        scope("invoice-42"),
    );
    let grants = repository.matching_grants(&facts, 1_000).unwrap();
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0].id().to_string(), grant_id.to_string());

    let route_facts = PolicyFacts::for_route(
        source.id(),
        action("billing.invoice.submit"),
        scope("invoice-42"),
        destination.id(),
    );
    assert!(
        repository
            .matching_grants(&route_facts, 1_000)
            .unwrap()
            .is_empty(),
        "a request-acceptance grant must not authorize a route decision"
    );

    create_grant(
        &mut administrator,
        grant_id,
        source.id().to_string(),
        "billing.invoice.submit",
        "*",
        None,
        0,
        None,
        correlation_id,
        1_000,
    );
    assert_eq!(
        repository.matching_grants(&facts, 1_000).unwrap().len(),
        1,
        "retrying the same correlation ID with identical content must not duplicate the grant"
    );

    let conflicting = administrator.query_opt(
        "SELECT * FROM create_authority_grant($1::text::uuid, $2::text::uuid, $3, $4, \
         NULL::uuid, $5, NULL::bigint, $6, $7, $8::text::uuid, $9)",
        &[
            &grant_id.to_string(),
            &source.id().to_string(),
            &"billing.invoice.cancel",
            &"*",
            &0i64,
            &"test-administrator",
            &"reason",
            &correlation_id.to_string(),
            &1_000i64,
        ],
    );
    assert!(
        conflicting.is_err(),
        "reusing a correlation ID with different content must be rejected"
    );

    let duplicate_grant_id = administrator.query_opt(
        "SELECT * FROM create_authority_grant($1::text::uuid, $2::text::uuid, $3, $4, \
         NULL::uuid, $5, NULL::bigint, $6, $7, $8::text::uuid, $9)",
        &[
            &grant_id.to_string(),
            &source.id().to_string(),
            &"work.item.submit",
            &"*",
            &0i64,
            &"test-administrator",
            &"reason",
            &Uuid::new_v4().to_string(),
            &1_000i64,
        ],
    );
    assert!(
        duplicate_grant_id.is_err(),
        "reusing a grant ID under a fresh correlation ID must be rejected"
    );

    let expired_id = Uuid::new_v4();
    create_grant(
        &mut administrator,
        expired_id,
        source.id().to_string(),
        "work.item.submit",
        "*",
        None,
        0,
        Some(500),
        Uuid::new_v4(),
        1_000,
    );
    let expired_facts =
        PolicyFacts::for_request_acceptance(source.id(), action("work.item.submit"), scope("*"));
    assert!(
        repository
            .matching_grants(&expired_facts, 1_000)
            .unwrap()
            .is_empty(),
        "an expired grant must not match"
    );

    assert!(
        administrator
            .execute(
                "UPDATE authority_grants SET scope = 'changed' WHERE grant_id = $1::text::uuid",
                &[&grant_id.to_string()],
            )
            .is_err(),
        "authority grants must be immutable"
    );
    assert!(
        administrator
            .execute(
                "DELETE FROM authority_grants WHERE grant_id = $1::text::uuid",
                &[&grant_id.to_string()],
            )
            .is_err(),
        "authority grants must be append-only"
    );
}

#[allow(clippy::too_many_arguments)]
fn create_grant(
    client: &mut Client,
    grant_id: Uuid,
    source_service_id: String,
    action: &str,
    scope: &str,
    destination_service_id: Option<String>,
    valid_from: i64,
    valid_until: Option<i64>,
    correlation_id: Uuid,
    created_at: i64,
) -> Row {
    client
        .query_one(
            "SELECT * FROM create_authority_grant($1::text::uuid, $2::text::uuid, $3, $4, \
             $5::text::uuid, $6, $7, $8, $9, $10::text::uuid, $11)",
            &[
                &grant_id.to_string(),
                &source_service_id,
                &action,
                &scope,
                &destination_service_id,
                &valid_from,
                &valid_until,
                &"test-administrator",
                &"integration test grant",
                &correlation_id.to_string(),
                &created_at,
            ],
        )
        .unwrap()
}

fn action(value: &str) -> ActionName {
    ActionName::new(value).unwrap()
}

fn scope(value: &str) -> Scope {
    Scope::new(value).unwrap()
}
