//! Goal: prove active-subscription discovery and per-kernel handshake history
//! operate together against live PostgreSQL.

use std::env;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use infernal_law::kernel::handshakes::{
    HandshakeAttemptOutcome, HandshakeError, HandshakeExchange, HandshakeTransport,
    SignedHandshakeChallenge, SignedHandshakeResponse,
};
use infernal_law::kernel::identity::ActorKind;
use infernal_law::kernel::instance_keys::{InstanceCredential, InstancePublicKey};
use infernal_law::kernel::subscriptions::EventType;
use infernal_law::wiring::Application;
use r2d2_postgres::postgres::{Client, NoTls};

struct SigningTransport {
    trusted_kernel: InstancePublicKey,
    target: Arc<InstanceCredential>,
}

impl HandshakeTransport for SigningTransport {
    fn exchange(
        &self,
        _: &str,
        challenge: &SignedHandshakeChallenge,
    ) -> Result<HandshakeExchange, HandshakeError> {
        challenge.verify_kernel(&self.trusted_kernel)?;
        Ok(HandshakeExchange {
            response: SignedHandshakeResponse::sign(challenge, &self.target)?,
            received_at: challenge.issued_at() + 1,
        })
    }
}

#[test]
#[ignore = "requires DATABASE_URL, INFERNAL_LAW_SERVICE_ID, and PostgreSQL with pgvector"]
fn each_kernel_instance_reconciles_only_distinct_active_subscribed_instances() {
    let now = unix_time();
    let first_kernel = Application::from_env().expect("first kernel should connect and migrate");
    let worker = first_kernel
        .identities()
        .create(ActorKind::Worker, "Handshake integration worker")
        .unwrap();
    let first_subscription = first_kernel
        .subscriptions()
        .create(
            worker.id(),
            EventType::new("artifact.submitted.v1").unwrap(),
            now,
        )
        .unwrap();
    let second_subscription = first_kernel
        .subscriptions()
        .create(
            worker.id(),
            EventType::new("decision.requested.v1").unwrap(),
            now,
        )
        .unwrap();
    let target = Arc::new(InstanceCredential::generate(worker.id()));
    let registered = first_kernel
        .instance_registry()
        .register_verified(
            target.public_key().clone(),
            "https://handshake-worker.example.test",
            now,
        )
        .unwrap();
    let target_id = registered.public_key().instance_id();
    let first_reconciler = first_kernel.handshake_reconciler(SigningTransport {
        trusted_kernel: first_kernel.instance_public_key().clone(),
        target: target.clone(),
    });
    let first_report = first_reconciler.reconcile(now + 1).unwrap();
    assert_eq!(
        first_report.attempts.len(),
        1,
        "two event subscriptions discover one instance"
    );
    assert!(matches!(
        first_report.attempts[0].outcome,
        HandshakeAttemptOutcome::Verified(_)
    ));
    assert!(first_reconciler.require_fresh(target_id, now + 2).is_ok());
    let first_kernel_instance = first_kernel.instance_public_key().instance_id();
    drop(first_reconciler);
    drop(first_kernel);

    let second_kernel = Application::from_env().expect("new kernel should reconnect");
    assert_ne!(
        second_kernel.instance_public_key().instance_id(),
        first_kernel_instance,
        "a restarted kernel must have a new ephemeral instance"
    );
    let second_reconciler = second_kernel.handshake_reconciler(SigningTransport {
        trusted_kernel: second_kernel.instance_public_key().clone(),
        target,
    });
    assert_eq!(
        second_reconciler.require_fresh(target_id, now + 2),
        Err(HandshakeError::HandshakeRequired(target_id)),
        "another kernel instance cannot reuse the first kernel's handshake"
    );
    assert!(matches!(
        second_reconciler.reconcile(now + 2).unwrap().attempts[0].outcome,
        HandshakeAttemptOutcome::Verified(_)
    ));

    second_kernel
        .subscriptions()
        .disable(worker.id(), first_subscription.id(), now + 3)
        .unwrap();
    second_kernel
        .subscriptions()
        .disable(worker.id(), second_subscription.id(), now + 3)
        .unwrap();
    assert!(
        second_reconciler
            .reconcile(now + 4)
            .unwrap()
            .attempts
            .is_empty()
    );
    assert_database_history(target_id);
}

fn assert_database_history(target_id: infernal_law::kernel::instance_keys::InstanceId) {
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be present");
    let mut client = Client::connect(&database_url, NoTls).expect("test database should connect");
    let id = target_id.to_string();
    let handshakes: i64 = client
        .query_one(
            "SELECT count(*) FROM service_instance_handshakes \
             WHERE target_instance_id = $1::text::uuid",
            &[&id],
        )
        .unwrap()
        .get(0);
    let pending: i64 = client
        .query_one(
            "SELECT count(*) FROM service_instance_handshake_challenges \
             WHERE target_instance_id = $1::text::uuid AND consumed_at IS NULL",
            &[&id],
        )
        .unwrap()
        .get(0);
    let audit: i64 = client
        .query_one(
            "SELECT count(*) FROM service_instance_handshake_audit \
             WHERE target_instance_id = $1::text::uuid",
            &[&id],
        )
        .unwrap()
        .get(0);
    assert_eq!(handshakes, 2);
    assert_eq!(pending, 0);
    assert_eq!(audit, 4, "each kernel appends issued and verified records");
    assert!(
        client
            .execute(
                "DELETE FROM service_instance_handshakes \
                 WHERE target_instance_id = $1::text::uuid",
                &[&id],
            )
            .is_err(),
        "verified handshake history must be append-only"
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
