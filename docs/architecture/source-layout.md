# Rust source layout

> Status: Active  
> Last reviewed: 2026-08-29

The crate separates the executable process from independently testable
library modules:

```text
src/
├── main.rs                 # thin executable entry point
├── lib.rs                  # public library boundary
├── http.rs                 # HTTP transport, governed-route dispatch, and
│                            # colocated unit tests
├── http/
│   ├── enrollment_dto.rs   # strict initial-enrollment JSON profile
│   └── subscription_dto.rs # ILK-010 subscription JSON wire format
├── infrastructure/
│   ├── mod.rs              # external-system adapter boundary
│   ├── database.rs         # pooled PostgreSQL and pgvector wiring
│   ├── kubernetes_token_reviewer.rs
│   │                        # bootstrap TokenReview adapter
│   ├── postgres_admission_repository.rs
│   │                        # read-only communication admission check
│   ├── postgres_authority_repository.rs
│   │                        # read-only ILK-002 grant matching
│   ├── http_policy_evaluator.rs
│   │                        # ILK-002 PolicyEvaluator over signed REST
│   ├── postgres_enrollment_binding_repository.rs
│   │                        # workload mappings and one-time challenges
│   ├── postgres_identity_repository.rs
│                            # PostgreSQL ILK-001 adapter
│   ├── postgres_instance_registry.rs
│                            # public keys, leases, revocation, audit
│   ├── postgres_replay_protection_repository.rs
│   │                        # atomic nonce/request-ID replay persistence
│   ├── postgres_request_repository.rs
│   │                        # ILK-003 durable acceptance and audit
│   ├── postgres_handshake_repository.rs
│   │                        # challenge consumption and handshake history
│   ├── postgres_subscribed_instance_discovery.rs
│   │                        # active-subscription/eligible-instance read model
│   └── postgres_subscription_repository.rs
│                            # ILK-010 persistence and append-only audit
├── wiring.rs               # process dependency construction
└── kernel/
    ├── mod.rs              # capability registry and registry tests
    ├── requirement.rs      # shared requirement metadata
    ├── admission.rs        # independent default-deny communication gate
    ├── identity.rs         # ILK-001
    ├── instance_keys.rs    # ephemeral per-process identity keys
    ├── instance_registry.rs
    │                       # kernel-owned public-key and lease contract
    ├── enrollment.rs       # initial workload/key authentication contract
    ├── handshakes.rs       # subscribed-instance proof reconciler and gate
    ├── service_requests.rs # fixed signed-HTTP verification profile
    ├── replay_protection.rs
    │                       # atomic nonce and request-ID contract
    ├── request_gate.rs     # signature/replay/admission composition
    ├── authority.rs        # ILK-002
    ├── requests.rs         # typed immutable ILK-003 core Request
    ├── versions.rs         # ILK-004
    ├── relationships.rs    # ILK-005
    ├── artifacts.rs        # ILK-006
    ├── decisions.rs        # ILK-007
    ├── audit.rs            # ILK-008
    ├── events.rs           # ILK-009
    ├── subscriptions.rs    # typed ILK-010 lifecycle contract
    ├── work_claims.rs      # ILK-011
    ├── idempotency.rs      # ILK-012
    └── mediation.rs        # ILK-013

tests/
├── database_connection.rs  # opt-in live PostgreSQL test
├── http_contract.rs        # independently runnable public HTTP test
├── identity_contract.rs    # independently runnable ILK-001 contract
├── authority_contract.rs   # independently runnable ILK-002 contract
├── request_contract.rs     # independently runnable ILK-003 contract
├── instance_keys_contract.rs
│                            # per-instance key isolation/signature contract
├── instance_registry_contract.rs
│                            # independently runnable lease-state contract
├── enrollment_contract.rs  # independently runnable enrollment policy
├── enrollment_json_contract.rs
│                            # independently runnable JSON DTO contract
├── enrollment_http_contract.rs
│                            # independently runnable POST handler contract
├── subscription_contract.rs
│                            # independently runnable ILK-010 contract
├── handshake_reconciler_contract.rs
│                            # isolated signed/failure-isolation contract
├── service_request_signature_contract.rs
│                            # isolated signed-HTTP verification contract
├── replay_protection_contract.rs
│                            # isolated atomic replay/safe-retry contract
├── admission_contract.rs   # isolated default-deny admission contract
├── service_request_gate_contract.rs
│                            # ordered fail-closed gate contract
├── governed_http_middleware_contract.rs
│                            # strict HTTP extraction/sanitization contract
├── infernal_client_rs_wire_compatibility.rs
│                            # proves infernal-client-rs's signed output
│                            # verifies against this kernel, and that a
│                            # kernel-signed request verifies via
│                            # infernal-client-rs's own verify_incoming
├── kernel_requirements.rs  # independently runnable public kernel test
├── postgres_identity_repository.rs
│                            # opt-in ILK-001 durability test
├── postgres_enrollment_bindings.rs
│                            # opt-in enrollment persistence test
├── postgres_subscription_repository.rs
│                            # opt-in ILK-010 durability/history test
├── postgres_handshake_reconciler.rs
│                            # opt-in discovery/handshake persistence test
├── postgres_replay_protection.rs
│                            # opt-in replay persistence/guard test
├── postgres_request_repository.rs
│                            # opt-in ILK-003 durability/history test
├── postgres_communication_admission.rs
│                            # opt-in admission administration/history test
├── postgres_authority_repository.rs
│                            # opt-in ILK-002 grant administration/read test
├── postgres_governed_http_middleware.rs
│                            # opt-in full governed HTTP gate composition
└── postgres_instance_registry.rs
                             # opt-in public-key/lease durability test
```

Each capability owns its implementation and private unit tests. Cross-module
behavior belongs in `tests/`, where it exercises only the crate's public API.
The binary contains no domain logic and delegates to the library.

## Running tests independently

Run one capability's colocated unit tests:

```sh
cargo test kernel::identity
cargo test kernel::work_claims
```

Run one integration-test file as its own test target:

```sh
cargo test --test http_contract
cargo test --test identity_contract
cargo test --test authority_contract
cargo test --test request_contract
cargo test --test instance_keys_contract
cargo test --test instance_registry_contract
cargo test --test enrollment_contract
cargo test --test enrollment_json_contract
cargo test --test enrollment_http_contract
cargo test --test subscription_contract
cargo test --test handshake_reconciler_contract
cargo test --test service_request_signature_contract
cargo test --test replay_protection_contract
cargo test --test admission_contract
cargo test --test service_request_gate_contract
cargo test --test governed_http_middleware_contract
cargo test --test infernal_client_rs_wire_compatibility
cargo test --test kernel_requirements
```

Run the live database wiring test after starting the pgvector container:

```sh
export DATABASE_URL='postgres://infernal_law:YOUR_PASSWORD@127.0.0.1:5432/infernal_law'
export INFERNAL_LAW_SERVICE_ID='00000000-0000-4000-8000-000000000001'
cargo test --test database_connection -- --ignored
cargo test --test postgres_identity_repository -- --ignored
cargo test --test postgres_instance_registry -- --ignored
cargo test --test postgres_enrollment_bindings -- --ignored
cargo test --test postgres_subscription_repository -- --ignored
cargo test --test postgres_handshake_reconciler -- --ignored
cargo test --test postgres_replay_protection -- --ignored
cargo test --test postgres_request_repository -- --ignored
cargo test --test postgres_communication_admission -- --ignored
cargo test --test postgres_authority_repository -- --ignored
cargo test --test postgres_governed_http_middleware -- --ignored
```

Run the complete suite before merging:

```sh
cargo test --all-targets
```

The initial capability modules establish traceability to the `ILK-*`
requirements. As behavior is implemented, its invariants and edge cases should
be tested in the owning module rather than in unrelated files.
