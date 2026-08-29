# Architecture

This directory describes the architecture of **infernal-law**. Keep these
documents close to the code and update them when the system changes.

## Start here

1. [System overview](system-overview.md) — purpose, context, components, and
   quality goals
2. [Minimum viable kernel](minimum-viable-kernel.md) — required capabilities,
   invariants, and acceptance criteria
3. [Rust source layout](source-layout.md) — independently testable module and
   test boundaries
4. [Direct service protocol](direct-service-protocol.md) — signed REST,
   database admission, subscriptions, health, and backpressure
5. [Data architecture](data.md) — PostgreSQL and vector-storage foundations
6. [Architecture decisions](decisions/README.md) — decisions and their
   rationale

## Documentation principles

- Describe the current system, not an idealized future version.
- Prefer small diagrams and links to code over duplicated implementation
  details.
- Record consequential choices as Architecture Decision Records (ADRs).
- State uncertainty and identify an owner for unresolved questions.
- Update relevant documents in the same change that alters the architecture.

## Suggested next documents

Add these only when the information becomes useful:

- `runtime-view.md` for important request, event, or job flows
- `deployment.md` for environments, infrastructure, and release topology
- `data.md` for ownership, storage, retention, and data movement
- `security.md` for trust boundaries, threats, and controls
- `operations.md` for observability, recovery, and failure handling
