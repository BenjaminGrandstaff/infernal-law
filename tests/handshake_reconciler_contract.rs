//! Goal: prove subscribed-instance reconciliation is mutually signed, failure
//! isolated, durable, and required before delivery eligibility.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use infernal_law::kernel::handshakes::{
    HandshakeAttemptOutcome, HandshakeChallengeRecord, HandshakeError, HandshakeExchange,
    HandshakeReconciler, HandshakeRepository, HandshakeTransport, InstanceHandshake,
    SignedHandshakeChallenge, SignedHandshakeResponse, SubscribedInstanceDiscovery,
};
use infernal_law::kernel::identity::ActorId;
use infernal_law::kernel::instance_keys::{InstanceCredential, InstanceId};
use infernal_law::kernel::instance_registry::RegisteredInstance;

#[derive(Clone)]
struct MemoryDiscovery(Vec<RegisteredInstance>);

impl SubscribedInstanceDiscovery for MemoryDiscovery {
    fn eligible_subscribed_instances(
        &self,
        now: i64,
    ) -> Result<Vec<RegisteredInstance>, HandshakeError> {
        Ok(self
            .0
            .iter()
            .filter(|instance| instance.is_eligible_at(now))
            .cloned()
            .collect())
    }
}

#[derive(Clone, Default)]
struct MemoryHandshakes {
    challenges: Arc<Mutex<Vec<(HandshakeChallengeRecord, bool)>>>,
    verified: Arc<Mutex<Vec<InstanceHandshake>>>,
}

impl HandshakeRepository for MemoryHandshakes {
    fn insert_challenge(&self, challenge: HandshakeChallengeRecord) -> Result<(), HandshakeError> {
        self.challenges.lock().unwrap().push((challenge, false));
        Ok(())
    }

    fn complete(&self, handshake: InstanceHandshake) -> Result<(), HandshakeError> {
        let mut challenges = self.challenges.lock().unwrap();
        let challenge = challenges
            .iter_mut()
            .find(|(challenge, consumed)| {
                challenge.digest() == handshake.challenge_digest()
                    && challenge.kernel_instance_id() == handshake.kernel_instance_id()
                    && challenge.target_instance_id() == handshake.target_instance_id()
                    && !*consumed
                    && challenge.expires_at() > handshake.verified_at()
            })
            .ok_or(HandshakeError::ChallengeAlreadyUsed)?;
        challenge.1 = true;
        self.verified.lock().unwrap().push(handshake);
        Ok(())
    }

    fn find_fresh(
        &self,
        kernel_instance_id: InstanceId,
        target_instance_id: InstanceId,
        now: i64,
    ) -> Result<Option<InstanceHandshake>, HandshakeError> {
        Ok(self
            .verified
            .lock()
            .unwrap()
            .iter()
            .rev()
            .find(|handshake| {
                handshake.kernel_instance_id() == kernel_instance_id
                    && handshake.target_instance_id() == target_instance_id
                    && handshake.is_fresh_at(now)
            })
            .cloned())
    }
}

struct SigningTransport {
    trusted_kernel: infernal_law::kernel::instance_keys::InstancePublicKey,
    targets: HashMap<InstanceId, Arc<InstanceCredential>>,
    unavailable: HashSet<InstanceId>,
    calls: Arc<Mutex<Vec<InstanceId>>>,
}

impl HandshakeTransport for SigningTransport {
    fn exchange(
        &self,
        _: &str,
        challenge: &SignedHandshakeChallenge,
    ) -> Result<HandshakeExchange, HandshakeError> {
        self.calls
            .lock()
            .unwrap()
            .push(challenge.target_instance_id());
        challenge.verify_kernel(&self.trusted_kernel)?;
        if self.unavailable.contains(&challenge.target_instance_id()) {
            return Err(HandshakeError::Transport("service unavailable".to_owned()));
        }
        let response = SignedHandshakeResponse::sign(
            challenge,
            self.targets
                .get(&challenge.target_instance_id())
                .ok_or(HandshakeError::TargetMismatch)?,
        )?;
        Ok(HandshakeExchange {
            response,
            received_at: challenge.issued_at() + 1,
        })
    }
}

fn registered(credential: &InstanceCredential, endpoint: &str) -> RegisteredInstance {
    RegisteredInstance::create(credential.public_key().clone(), endpoint, 90, 200).unwrap()
}

#[test]
fn unavailable_subscriber_does_not_block_other_handshakes() {
    let kernel = Arc::new(InstanceCredential::generate(ActorId::new()));
    let available = Arc::new(InstanceCredential::generate(ActorId::new()));
    let unavailable = Arc::new(InstanceCredential::generate(ActorId::new()));
    let available_instance = registered(&available, "https://available.example.test");
    let unavailable_instance = registered(&unavailable, "https://unavailable.example.test");
    let available_id = available.public_key().instance_id();
    let unavailable_id = unavailable.public_key().instance_id();
    let repository = MemoryHandshakes::default();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let transport = SigningTransport {
        trusted_kernel: kernel.public_key().clone(),
        targets: HashMap::from([(available_id, available), (unavailable_id, unavailable)]),
        unavailable: HashSet::from([unavailable_id]),
        calls: calls.clone(),
    };
    let reconciler = HandshakeReconciler::new(
        kernel,
        MemoryDiscovery(vec![unavailable_instance, available_instance]),
        repository.clone(),
        transport,
    );

    let report = reconciler.reconcile(100).unwrap();

    assert_eq!(report.attempts.len(), 2);
    assert!(matches!(
        report.attempts[0].outcome,
        HandshakeAttemptOutcome::Failed(HandshakeError::Transport(_))
    ));
    assert!(matches!(
        report.attempts[1].outcome,
        HandshakeAttemptOutcome::Verified(_)
    ));
    assert!(reconciler.require_fresh(available_id, 101).is_ok());
    assert_eq!(
        reconciler.require_fresh(unavailable_id, 101),
        Err(HandshakeError::HandshakeRequired(unavailable_id))
    );
    assert_eq!(calls.lock().unwrap().len(), 2);
}

#[test]
fn fresh_handshake_is_reused_and_expiry_closes_delivery_gate() {
    let kernel = Arc::new(InstanceCredential::generate(ActorId::new()));
    let target = Arc::new(InstanceCredential::generate(ActorId::new()));
    let instance = registered(&target, "https://target.example.test");
    let target_id = target.public_key().instance_id();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let reconciler = HandshakeReconciler::new(
        kernel.clone(),
        MemoryDiscovery(vec![instance]),
        MemoryHandshakes::default(),
        SigningTransport {
            trusted_kernel: kernel.public_key().clone(),
            targets: HashMap::from([(target_id, target)]),
            unavailable: HashSet::new(),
            calls: calls.clone(),
        },
    );

    assert!(matches!(
        reconciler.reconcile(100).unwrap().attempts[0].outcome,
        HandshakeAttemptOutcome::Verified(_)
    ));
    assert!(matches!(
        reconciler.reconcile(110).unwrap().attempts[0].outcome,
        HandshakeAttemptOutcome::AlreadyFresh(_)
    ));
    assert_eq!(calls.lock().unwrap().len(), 1);
    assert_eq!(
        reconciler.require_fresh(target_id, 131),
        Err(HandshakeError::HandshakeRequired(target_id))
    );
}
