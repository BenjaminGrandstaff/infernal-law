# Rust source layout

> Status: Active  
> Last reviewed: 2026-08-28

The crate separates the executable process from independently testable
library modules:

```text
src/
├── main.rs                 # thin executable entry point
├── lib.rs                  # public library boundary
├── http.rs                 # HTTP transport and colocated unit tests
├── infrastructure/
│   ├── mod.rs              # external-system adapter boundary
│   ├── database.rs         # pooled PostgreSQL and pgvector wiring
│   ├── kubernetes_token_reviewer.rs
│   │                        # bootstrap TokenReview adapter
│   ├── postgres_enrollment_binding_repository.rs
│   │                        # workload mappings and one-time challenges
│   ├── postgres_identity_repository.rs
│                            # PostgreSQL ILK-001 adapter
│   └── postgres_instance_registry.rs
│                            # public keys, leases, revocation, audit
├── wiring.rs               # process dependency construction
└── kernel/
    ├── mod.rs              # capability registry and registry tests
    ├── requirement.rs      # shared requirement metadata
    ├── identity.rs         # ILK-001
    ├── instance_keys.rs    # ephemeral per-process identity keys
    ├── instance_registry.rs
    │                       # kernel-owned public-key and lease contract
    ├── enrollment.rs       # initial workload/key authentication contract
    ├── authority.rs        # ILK-002
    ├── resources.rs        # ILK-003
    ├── versions.rs         # ILK-004
    ├── relationships.rs    # ILK-005
    ├── artifacts.rs        # ILK-006
    ├── decisions.rs        # ILK-007
    ├── audit.rs            # ILK-008
    ├── events.rs           # ILK-009
    ├── subscriptions.rs    # ILK-010
    ├── work_claims.rs      # ILK-011
    ├── idempotency.rs      # ILK-012
    └── mediation.rs        # ILK-013

tests/
├── database_connection.rs  # opt-in live PostgreSQL test
├── http_contract.rs        # independently runnable public HTTP test
├── identity_contract.rs    # independently runnable ILK-001 contract
├── instance_keys_contract.rs
│                            # per-instance key isolation/signature contract
├── instance_registry_contract.rs
│                            # independently runnable lease-state contract
├── enrollment_contract.rs  # independently runnable enrollment policy
├── kernel_requirements.rs  # independently runnable public kernel test
├── postgres_identity_repository.rs
│                            # opt-in ILK-001 durability test
├── postgres_enrollment_bindings.rs
│                            # opt-in enrollment persistence test
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
cargo test --test instance_keys_contract
cargo test --test instance_registry_contract
cargo test --test enrollment_contract
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
```

Run the complete suite before merging:

```sh
cargo test --all-targets
```

The initial capability modules establish traceability to the `ILK-*`
requirements. As behavior is implemented, its invariants and edge cases should
be tested in the owning module rather than in unrelated files.
