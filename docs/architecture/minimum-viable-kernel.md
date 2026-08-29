# Minimum viable kernel

> Status: Requirements draft  
> Last reviewed: 2026-08-28  
> Owners: TODO

## Objective

The minimum viable Infernal-Law kernel is a trusted mediation boundary for
governed work. It identifies callers, decides whether operations are
authorized, preserves durable state and evidence, records consequential
actions, and coordinates workers without permitting them to mutate kernel
state directly. The kernel implementation target is Rust, with PostgreSQL as
its durable system of record.

The keywords **MUST**, **MUST NOT**, **SHOULD**, and **MAY** express requirement
strength. Every capability in this document is required for the minimum viable
kernel unless it is explicitly marked otherwise.

## Terms

- **Service principal** — a backend service admitted to the kernel with a
  stable identity and one or more registered public keys.
- **Worker** — a service principal that consumes events or claims work for
  processing.
- **External user subject** — optional provenance asserted by an authenticated
  service; it is not a kernel principal or credential.
- **Operation** — a command submitted through a kernel contract.
- **Resource** — a durable object governed by the kernel.
- **Artifact** — immutable evidence or a result submitted by a worker.
- **Kernel contract** — an authenticated command or query interface owned by
  the kernel.

## Core requirements

| ID | Capability | Minimum requirement |
| --- | --- | --- |
| ILK-001 | Identity | Every calling service and worker has a stable service identity. |
| ILK-002 | Authority | The kernel determines whether an identity may perform an operation. |
| ILK-003 | Resources | Governed objects are durable and have stable, non-reusable IDs. |
| ILK-004 | Versions | Resources are versioned; accepted history is never silently overwritten. |
| ILK-005 | Relationships | Resources can be connected by typed links. |
| ILK-006 | Artifacts | Workers can submit immutable evidence and results. |
| ILK-007 | Decisions | Governed decisions are explicit durable records. |
| ILK-008 | Audit | Security and governance actions produce append-only audit records. |
| ILK-009 | Events | Committed changes can produce typed events. |
| ILK-010 | Subscriptions | Workers can declare the event types in which they are interested. |
| ILK-011 | Work claims | At most one worker can hold the active claim for a piece of work. |
| ILK-012 | Idempotency | Retrying a request cannot accidentally perform it twice. |
| ILK-013 | Mediation | Workers use kernel contracts and cannot directly mutate kernel state. |

## Capability invariants and acceptance criteria

### ILK-001: Identity

- Implementation: `src/kernel/identity.rs`
- Independent contract test: `tests/identity_contract.rs`

Invariants:

- Every non-public operation MUST be attributable to exactly one authenticated
  service identity and verified public key.
- Every running service instance MUST have a unique instance ID and freshly
  generated keypair; no private key may be shared with another instance or
  persisted outside its signing process.
- Identity IDs MUST remain stable even if display names or credentials change.
- Worker identities MUST be represented as a service role or profile.
- The kernel MUST NOT accept user credentials as kernel credentials.

Acceptance criteria:

- A request without a valid, fresh HTTP message signature from an enabled
  service is rejected before governed state is read or changed.
- A completed operation can be traced back to the stable service ID that
  requested it.
- Restarting a service process creates a new instance ID and key and requires a
  new proof-of-possession handshake.

Implementation status:

- Complete: stable UUID IDs, service/worker distinction, active and disabled
  lifecycle, display-name validation, repository contract, and independently
  testable service behavior.
- Complete: PostgreSQL identity repository, schema constraints, migration, and
  restart-durability integration test.
- Complete: the domain and database schema reject human identities and accept
  only service and worker principals.
- Complete: unique per-process instance and key IDs, ephemeral Ed25519 signing
  keys, public verification records, and process-wide application wiring.
- Complete: kernel-owned PostgreSQL public-key registration, immutable key
  records, bounded compare-and-set leases, revocation, and append-only registry
  audit storage behind a typed repository contract.
- Complete: authenticated initial enrollment, kernel-to-subscriber discovery
  handshakes, and fixed-profile Ed25519 HTTP Message Signature verification
  covering the request method, target URI, content, stable service, instance,
  key, and request ID with bounded signature timestamps.
- Complete: atomic PostgreSQL nonce-digest consumption, permanent
  service/request-ID fingerprint binding, safe-retry classification, conflict
  rejection, and append-only accepted/rejected replay audit.
- Pending: signed lease-renewal transport, transport middleware for governed
  routes, and database communication admission.
- Pending: mediation and audit integration that attributes every completed
  operation to that service and signing key.

See the [direct service protocol](direct-service-protocol.md) and
[ADR-0003](decisions/0003-direct-signed-service-rest.md).
Instance key and discovery lifecycle is specified by
[ADR-0005](decisions/0005-use-ephemeral-per-instance-service-keys.md).

### ILK-002: Authority

Invariants:

- The kernel MUST authorize an operation before changing governed state.
- Authorization MUST default to denial when no applicable grant or policy
  permits an operation.
- The decision MUST consider the actor, operation, and target resource or
  resource type.

Acceptance criteria:

- The same operation succeeds for an authorized identity and fails for an
  unauthorized identity without changing state.
- Security-relevant authorization outcomes have enough context to be audited.

### ILK-003: Resources

Invariants:

- Every resource MUST have a stable, globally unique ID independent of its
  name or current version.
- An ID MUST NOT be reassigned to a different logical resource.
- Resource creation MUST be durable before the kernel reports success.

Acceptance criteria:

- Renaming or versioning a resource does not change its ID.
- A successfully created resource remains addressable after process restart.

### ILK-004: Versions

Invariants:

- A mutation MUST create a new resource version rather than overwrite an
  accepted version.
- Each version MUST identify its resource, predecessor where applicable,
  creation time, and responsible actor.
- Concurrent updates based on stale state MUST be detected and rejected or
  explicitly reconciled.

Acceptance criteria:

- All accepted versions of a resource can be retrieved in order.
- Two writers cannot silently replace each other's changes.

### ILK-005: Relationships

Invariants:

- Every relationship MUST have a declared type and stable source and target
  resource IDs.
- Relationship endpoints MUST refer to existing resources unless a documented
  relationship type explicitly permits an external endpoint.
- Relationship history MUST follow the same non-destructive versioning rule as
  resources.

Acceptance criteria:

- Callers can query relationships by type and endpoint.
- The kernel rejects an unknown relationship type or invalid endpoint.

### ILK-006: Artifacts

Invariants:

- An accepted artifact's content and provenance metadata MUST be immutable.
- Each artifact MUST identify its submitting worker, creation time, media or
  schema type, and the work or resource to which it relates.
- A correction MUST create a new artifact and link to the artifact it replaces
  or supplements.

Acceptance criteria:

- An artifact can be retrieved and verified as the exact content originally
  accepted.
- An attempt to update artifact content is rejected.

### ILK-007: Decisions

Invariants:

- A governed decision MUST be stored as a first-class record, not inferred
  solely from current resource state or log text.
- A decision MUST record its type, outcome, responsible actor, time, relevant
  inputs, and affected resources.
- Reversal or supersession MUST create another decision linked to the earlier
  record.

Acceptance criteria:

- A caller can reconstruct what was decided, by whom, and from which recorded
  inputs.
- Reversing a decision leaves the earlier decision available.

### ILK-008: Audit

Invariants:

- Security and governance actions MUST append an audit record in the same
  successful transaction as their governed state change.
- Audit records MUST NOT be updated or deleted through kernel contracts.
- Each record MUST include an event type, service ID, time, operation, target,
  outcome, and correlation ID.

Acceptance criteria:

- A successful governed change has a corresponding audit record.
- A rejected security-sensitive operation produces an audit record without a
  governed state change.
- Normal application credentials cannot update or delete audit history.

### ILK-009: Events

Invariants:

- An event MUST describe an already committed fact and MUST NOT announce a
  state change that can later roll back.
- Every event MUST have a stable event ID, declared type and schema version,
  occurrence time, and correlation ID.
- When an operation promises an event, durable state and the event MUST be
  committed atomically.

Acceptance criteria:

- A failed or rolled-back operation publishes no committed-change event.
- Consumers can distinguish event types and schema versions without inspecting
  an untyped payload.

### ILK-010: Subscriptions

- Implementation: `src/kernel/subscriptions.rs`
- Independent contract test: `tests/subscription_contract.rs`

Invariants:

- A worker MUST be able to create, inspect, and disable its subscriptions
  through kernel contracts.
- A subscription MUST identify the worker and one or more declared event types.
- Subscription changes MUST be authorized and audited.
- Delivery MUST obey the shared readiness/capacity health model without
  deleting or disabling durable subscription state.
- Every kernel instance MUST continuously discover reachable instances for
  active subscriptions and complete a fresh, mutual proof-of-possession
  handshake before delivering to an instance.

Acceptance criteria:

- A worker receives or can retrieve only events matching its active
  subscriptions and authorization scope.
- Disabling a subscription prevents new deliveries without deleting its
  history.
- Saturation, stale health, or lack of capacity pauses delivery and later
  resumes from the last durable cursor.
- One unreachable subscriber does not prevent kernel startup or discovery of
  other subscribers; its delivery remains paused and is retried with backoff.

Implementation status:

- Complete: typed subscription UUIDs and event types; stable-service ownership;
  durable create, history list, active list, and disable contracts; one-active
  subscription uniqueness; append-only create/disable audit; protected disabled
  history; PostgreSQL adapter; distinct eligible-instance discovery; per-kernel
  signed proof-of-possession reconciliation; append-only handshake persistence;
  failure isolation; fresh-handshake delivery gate; and isolated plus live
  persistence tests.
- Pending: signed REST operations, ILK-002 authorization integration, delivery
  cursors, production outbound handshake transport, and capacity-aware delivery.

### ILK-011: Work claims

Invariants:

- At most one unexpired active claim may exist for the same work item.
- Claim acquisition and renewal MUST be atomic.
- Claims MUST expire or be explicitly released so abandoned work can be
  recovered.
- Only the current claim holder may complete or release claimed work.

Acceptance criteria:

- Concurrent claim attempts produce exactly one active holder.
- Another worker can claim work after the prior claim expires.
- A stale holder cannot complete work after losing its claim.

### ILK-012: Idempotency

Invariants:

- Mutating operations MUST accept an idempotency key scoped to the actor and
  operation.
- Repeating the same request with the same key MUST return the original result
  and MUST NOT repeat its effects.
- Reusing a key with a materially different request MUST be rejected.
- Concurrent requests with the same key MUST converge on one committed result.

Acceptance criteria:

- Retrying after a lost response creates only one resource version, decision,
  artifact, audit change, and promised event.
- A key collision with a different payload returns a deterministic conflict.

### ILK-013: Mediation

Invariants:

- Workers MUST mutate governed state only through authenticated kernel
  contracts.
- No caller, including an administrative service, may submit SQL or database
  command fragments for the kernel to execute.
- Worker credentials MUST NOT grant direct write access to kernel-owned tables,
  event storage, or audit history.
- Kernel persistence adapters MUST use kernel-owned statement structure and
  bound values; caller-controlled identifiers or SQL structure are prohibited.
- The kernel MUST enforce identity, authority, validation, idempotency,
  versioning, audit, and event rules at the mediation boundary.

Acceptance criteria:

- A worker can complete its supported workflow using only kernel contracts.
- A worker's runtime credentials cannot directly insert, update, or delete
  kernel-owned records.
- SQL-shaped operations are rejected before a repository or database adapter
  is called.
- Bypassing one contract cannot bypass the cross-cutting kernel invariants.

## Transaction boundary

For an accepted mutating operation, the following effects MUST form one atomic
transaction where applicable:

1. validate identity, authority, input, and idempotency;
2. create the resource version, relationship, artifact, decision, subscription,
   or claim change;
3. append required audit records;
4. append promised events; and
5. persist the idempotent result.

The kernel reports success only after this transaction commits. Delivery of a
committed event to a subscriber MAY occur asynchronously.

## Minimum verification strategy

Each requirement MUST have automated tests at the lowest practical layer:

- unit tests for policy and state-transition rules;
- database integration tests for immutability, uniqueness, concurrency, and
  transaction rollback;
- contract tests for authentication, authorization, validation, and
  idempotency behavior; and
- end-to-end tests for event delivery, subscriptions, claim recovery, and
  mediated worker workflows.

## Open design decisions

The requirements intentionally do not choose these implementation details:

- identity provider and credential format;
- authorization model and policy language;
- resource and relationship type registries;
- artifact storage location and integrity mechanism;
- event transport and delivery guarantee;
- subscription cursor and replay semantics;
- claim lease duration and renewal protocol;
- idempotency retention period; and
- public kernel contract protocol and schema format.

Each consequential choice should be recorded as an ADR and linked back to the
affected `ILK-*` requirements.
