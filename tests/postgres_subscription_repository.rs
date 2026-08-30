//! Goal: prove ILK-010 subscription history, active uniqueness, auditing, and
//! stable-service ownership in live PostgreSQL.

use std::env;
use std::time::{SystemTime, UNIX_EPOCH};

use infernal_law::kernel::identity::{ActorId, ActorKind};
use infernal_law::kernel::subscriptions::{DeliveryMode, EventType, SubscriptionError};
use infernal_law::wiring::Application;
use r2d2_postgres::postgres::{Client, NoTls};

#[test]
#[ignore = "requires DATABASE_URL, INFERNAL_LAW_SERVICE_ID, and PostgreSQL with pgvector"]
fn subscription_history_survives_reconnection_and_rejects_destructive_mutation() {
    let first_process = Application::from_env().expect("application should connect and migrate");
    let service = first_process
        .identities()
        .create(ActorKind::Worker, "Subscription integration worker")
        .expect("stable worker identity should be stored");
    let event_type = EventType::new(&format!("test.subscription-{}.v1", service.id())).unwrap();
    let now = unix_time();

    let first = first_process
        .subscriptions()
        .create(
            service.id(),
            event_type.clone(),
            DeliveryMode::Inclusive,
            now,
        )
        .unwrap();
    assert!(matches!(
        first_process.subscriptions().create(
            service.id(),
            event_type.clone(),
            DeliveryMode::Inclusive,
            now + 1,
        ),
        Err(SubscriptionError::DuplicateActive(id, event))
            if id == service.id() && event == event_type
    ));
    first_process
        .subscriptions()
        .disable(service.id(), first.id(), now + 2)
        .unwrap();
    let second = first_process
        .subscriptions()
        .create(
            service.id(),
            event_type.clone(),
            DeliveryMode::Inclusive,
            now + 3,
        )
        .unwrap();

    let matching = first_process
        .subscriptions()
        .find_active_by_event_type(&event_type)
        .unwrap();
    assert_eq!(matching.len(), 1);
    assert_eq!(matching[0].id(), second.id());
    drop(first_process);

    let second_process = Application::from_env().expect("application should reconnect");
    let history = second_process.subscriptions().list(service.id()).unwrap();
    let active = second_process
        .subscriptions()
        .list_active(service.id())
        .unwrap();
    assert_eq!(history.len(), 2);
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].id(), second.id());
    assert_eq!(active[0].service_id(), service.id());

    assert_database_guards(service.id(), first.id(), second.id());
    let unknown_service = ActorId::new();
    assert_eq!(
        second_process.subscriptions().create(
            unknown_service,
            EventType::new("unknown.service-event.v1").unwrap(),
            DeliveryMode::Inclusive,
            now + 4,
        ),
        Err(SubscriptionError::UnknownService(unknown_service))
    );
}

fn assert_database_guards(
    service_id: ActorId,
    first_id: infernal_law::kernel::subscriptions::SubscriptionId,
    second_id: infernal_law::kernel::subscriptions::SubscriptionId,
) {
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be present");
    let mut client = Client::connect(&database_url, NoTls).expect("test database should connect");
    let audit_count: i64 = client
        .query_one(
            "SELECT count(*) FROM subscription_audit WHERE service_id = $1::text::uuid",
            &[&service_id.to_string()],
        )
        .unwrap()
        .get(0);
    assert_eq!(audit_count, 3, "create, disable, and re-create are audited");

    assert!(
        client
            .execute(
                "DELETE FROM subscriptions WHERE id = $1::text::uuid",
                &[&first_id.to_string()],
            )
            .is_err(),
        "subscription history must reject deletion"
    );
    assert!(
        client
            .execute(
                "UPDATE subscriptions SET event_type = 'changed.v1' \
                 WHERE id = $1::text::uuid",
                &[&second_id.to_string()],
            )
            .is_err(),
        "subscription identity and event type must be immutable"
    );
    assert!(
        client
            .execute(
                "DELETE FROM subscription_audit WHERE service_id = $1::text::uuid",
                &[&service_id.to_string()],
            )
            .is_err(),
        "subscription audit must be append-only"
    );
}

fn unix_time() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock must be after Unix epoch")
            .as_secs(),
    )
    .expect("Unix time must fit in i64")
}
