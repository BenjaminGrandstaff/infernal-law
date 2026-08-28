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
└── kernel/
    ├── mod.rs              # capability registry and registry tests
    ├── requirement.rs      # shared requirement metadata
    ├── identity.rs         # ILK-001
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
├── http_contract.rs        # independently runnable public HTTP test
└── kernel_requirements.rs  # independently runnable public kernel test
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
cargo test --test kernel_requirements
```

Run the complete suite before merging:

```sh
cargo test --all-targets
```

The initial capability modules establish traceability to the `ILK-*`
requirements. As behavior is implemented, its invariants and edge cases should
be tested in the owning module rather than in unrelated files.
