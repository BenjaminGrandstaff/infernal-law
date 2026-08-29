# System overview

> Status: Draft  
> Last reviewed: 2026-08-28  
> Owners: TODO

## Purpose

**Infernal-Law** is a governance kernel that mediates work performed by
authenticated service principals, including workers. User authentication is a
separate service responsibility. The kernel provides durable, versioned
resources and evidence while making authority, decisions, audit history,
events, and work coordination explicit and traceable.

Services know the kernel contract, not one another's identity or runtime
topology. The kernel provides store-and-forward delivery: it durably retains a
request when no matching service subscription exists, then materializes an
independent route for each matching destination when subscribers appear.

PostgreSQL is the only authoritative kernel state. Rust processes and
Kubernetes pods are ephemeral compute: after failure they rebuild every queue,
cursor, route, lease, and decision from PostgreSQL and never continue governed
work from process memory or a local filesystem.

## Scope

### In scope

- Identity-aware and authorized kernel operations
- Direct public/private-key-signed REST communication and database-backed
  admission of service principals
- Durable, versioned resources, relationships, artifacts, and decisions
- Append-only audit history and committed-change events
- Worker subscriptions, exclusive work claims, and idempotent requests
- A mediation boundary that prevents workers from directly mutating kernel
  state

### Out of scope

- Direct worker access to kernel-owned persistence
- Caller-supplied SQL, database queries, procedure names, or database command
  passthrough APIs
- User registration, user credentials, sessions, and account recovery
- Silently destructive updates to accepted history
- Application-specific worker behavior beyond kernel coordination contracts
- Scheduling policy: which eligible route runs next, worker/node preference,
  priority, affinity, resource-class (for example GPU) placement, capacity
  accounting, backpressure, and retry timing. These belong to an external
  scheduler service — see
  [ADR-0011](decisions/0011-move-scheduling-policy-outside-the-kernel.md) and
  the reference `infernal-taskmaster-simple` implementation.
- Non-Rust language bindings and in-process linking of kernel code. Every
  caller, in every language, reaches the kernel only over the signed REST
  contract from ADR-0003 — see
  [ADR-0012](decisions/0012-rust-first-client-sdk-family-over-signed-rest.md)
  and the `infernal-client-*` repositories.
- Capabilities beyond the documented [minimum viable kernel](minimum-viable-kernel.md)
  until they are separately specified

## System context

TODO: List the people and external systems that interact with infernal-law.
Replace this placeholder with a context diagram once those relationships are
known.

| Participant or system | Relationship | Data exchanged |
| --- | --- | --- |
| User-authentication service | Authenticates users outside the kernel and calls through its workload identity | External subject assertions and commands |
| Backend service | Sends direct signed REST operations | HTTP message signatures, commands, query results |
| Worker service | Subscribes, reports health/capacity, claims work, and submits artifacts | Signed REST, events, claims, evidence, results |
| Administrative program | Toggles durable communication admission | Audited database admission-state changes |
| Event consumer or transport | Delivers committed facts to workers | Typed, versioned events |

## Major components

| Component | Responsibility | Technology | Source |
| --- | --- | --- | --- |
| HTTP service | Exposes the application and health endpoints | Rust | `src/` |
| Container image | Packages the service as a non-root process | Podman/OCI | `Containerfile` |
| Database | Sole authoritative kernel state, recovery source, and relational/vector store | PostgreSQL 17 with pgvector | `containers/postgres/` |
| Runtime deployment | Runs and exposes the service | Kubernetes | `k8s/base/` |
| Instance key agent | Generates a unique in-process keypair and registers only the leased public record through the kernel | Rust/kernel REST API | Partial |
| Initial enrollment verifier | Binds key possession to Kubernetes TokenReview and an enabled workload mapping | Rust/Kubernetes/PostgreSQL | Implemented |
| Instance registry | Owns public keys, bounded leases, and registration history | Rust/PostgreSQL | Implemented |
| Subscription registry | Owns typed stable-service event interests and immutable disabled history | Rust/PostgreSQL | Implemented; REST pending |
| Kernel discovery reconciler | Finds subscribed instances and performs per-kernel mutual proof-of-possession handshakes | Rust/PostgreSQL | Implemented; outbound HTTP transport pending |
| Service request verifier | Verifies the fixed signed-HTTP profile against eligible registry keys and returns typed caller context | Rust | Implemented |
| Replay protector | Atomically consumes key-scoped nonce digests and binds stable request IDs to semantic request fingerprints | Rust/PostgreSQL | Implemented; idempotent result storage pending |
| Request store | Durably accepts requests keyed on `(source_service_id, request_id)`, classifying safe retries and rejecting rebinding | Rust/PostgreSQL | Implemented; envelope, artifact, and route materialization pending |
| Communication admission | Independently stores default-deny service communication state and immutable administrative history | Rust/PostgreSQL | Implemented and connected to governed HTTP gate |
| Governed HTTP gate | Strictly parses security headers and composes signature, replay, and admission before handlers | Rust/PostgreSQL | Implemented; Authority and governed handlers pending |

## Key flows

### Governed mutation

1. A service sends a timestamped, signed, idempotent REST operation directly to
   the kernel/hub.
2. The kernel verifies the public key, HTTP message signature, content digest,
   timestamp, nonce, replay state, and database communication-admission flag.
3. The kernel checks authority and validates current versioned state.
4. The kernel atomically stores the state change, audit record, promised event,
   and idempotent result.
5. If no eligible subscriber exists, the request or event remains durably
   unrouted; acceptance is not rolled back and the source need not discover a
   receiver.
6. Each matching subscription destination gets one idempotently materialized
   route with independent progress and completion history.
7. The kernel exposes incomplete, unclaimed routes eligible under admission,
   authority, and handshake state. An external scheduler service selects which
   eligible route runs next and on which worker, applying its own health,
   capacity, and placement policy, then requests a claim; the kernel grants it
   only after re-checking authorization, eligibility, and fencing, and records
   completion only for that route's subscription destination.

## Data

PostgreSQL is the system of record for all kernel-owned state and pgvector
provides vector-column and similarity-search support. Application processes
hold no recoverable state. The remaining schema, retention, backup, and
sensitivity details are defined or tracked in the
[data architecture](data.md).

## Quality goals

Rank the few qualities that drive architectural tradeoffs.

| Priority | Quality | Concrete scenario or target |
| ---: | --- | --- |
| 1 | Integrity | No caller can bypass authority, versioning, or mediation rules to mutate governed state. |
| 2 | Traceability | A governed outcome can be reconstructed from identities, versions, decisions, artifacts, and audit records. |
| 3 | Retry and concurrency safety | Duplicate requests and competing workers cannot create duplicate effects or simultaneous active claims. |

## Constraints

- The project is distributed under the MIT License.
- The project is classified as EAR99 for U.S. export-control purposes. See the
  [export-control notice](../export-control.md).
- All minimum kernel behavior must satisfy the invariants in the
  [minimum viable kernel specification](minimum-viable-kernel.md).
- TODO: Other legal, organizational, technical, cost, or delivery constraint

## Risks and open questions

| Item | Impact | Owner | Next step |
| --- | --- | --- | --- |
| TODO | TODO | TODO | TODO |

## Related decisions

- [ADR-0003: Use direct signed REST communication](decisions/0003-direct-signed-service-rest.md)
- [ADR-0005: Use ephemeral per-instance service keys](decisions/0005-use-ephemeral-per-instance-service-keys.md)
- [ADR-0009: Use explicit subscription delivery modes and leased route assignments](decisions/0009-use-explicit-subscription-delivery-modes.md)
- [ADR-0010: Use PostgreSQL as the only kernel state store](decisions/0010-use-postgresql-as-the-only-kernel-state-store.md)
- [ADR-0006: Store instance public keys and leases in PostgreSQL](decisions/0006-store-instance-public-keys-in-postgresql.md)
- [ADR-0007: Expose no SQL command surface](decisions/0007-expose-no-sql-command-surface.md)
- [ADR-0008: Use Kubernetes TokenReview for initial enrollment](decisions/0008-use-kubernetes-tokenreview-for-initial-enrollment.md)
