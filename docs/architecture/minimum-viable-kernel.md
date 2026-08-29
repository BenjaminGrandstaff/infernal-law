# Minimum viable kernel

> Status: Requirements draft  
> Last reviewed: 2026-08-29
> Owners: TODO

## Objective

The minimum viable Infernal-Law kernel is a zero-trust communication hub and
trusted mediation boundary for governed work. It authenticates connections,
accepts and routes durable requests, applies administrator-controlled security
policy, coordinates work, and records consequential actions without owning the
business object model of every connected service. The kernel implementation
target is Rust, with PostgreSQL as its durable system of record.

The only general non-administrative object defined by the kernel is a
**Request**. Connected services own the schemas, action vocabulary, artifacts,
and permission-policy vocabulary for their business domains. The kernel owns
security, administration, connection, routing, subscription, work-coordination,
audit, replay, and idempotency records needed to mediate those requests.

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
- **Request** — the immutable, signed, durable communication envelope submitted
  by one service for a destination service or kernel coordination function.
- **Action name** — a service-owned, namespaced action declared by an approved
  artifact and permission-policy schema; it is not a kernel-wide enum.
- **Artifact** — service-owned content carried by reference or value in a
  request. The kernel treats its business content as opaque except for approved
  schema metadata, routing fields, content length, and content digest.
- **Artifact schema** — a namespaced, versioned contract defined by the service
  that owns an artifact type.
- **Permission-policy schema** — a namespaced, versioned declaration from a
  service describing the actions and permission fields meaningful for its
  artifacts. Administrators, not the defining service, control activation and
  grants under that schema.
- **Administrative object** — kernel-owned security, connection, schema
  registration, policy activation, grant, routing, subscription, work, audit,
  replay, or idempotency state.
- **Kernel contract** — an authenticated command or query interface owned by
  the kernel.

## Kernel object boundary

The kernel MUST NOT grow a universal business-resource model. A request MAY
refer to service-owned artifacts, but the kernel MUST NOT require Rust types
for every invoice, document, model, medical record, or future service object.
A governed request MUST carry or resolve at least:

- a stable request ID;
- authenticated source service, instance, and key IDs;
- a destination service or explicit kernel coordination destination;
- a namespaced action;
- artifact type, schema name, schema version, and schema owner;
- permission-policy schema name, version, and owner;
- artifact ID or payload reference plus content digest;
- correlation and optional causation IDs; and
- creation, expiry, replay, and idempotency metadata.

A service MAY publish new artifact and permission-policy schemas in its own
namespace. Publication MUST NOT activate a schema, authorize the publisher, or
create a grant. A security administrator MUST explicitly approve schema
versions and bind identities to permissions. The kernel MUST make and retain
the final allow-or-deny result.

## Core requirements

| ID | Capability | Minimum requirement |
| --- | --- | --- |
| ILK-001 | Identity | Every calling service and worker has a stable service identity. |
| ILK-002 | Authority | The kernel determines whether a source may submit a request under an approved service-defined permission schema. |
| ILK-003 | Requests | Governed communications are immutable durable requests with stable, non-reusable IDs. |
| ILK-004 | Versions | Requests, schemas, policies, and administrative history are never silently overwritten. |
| ILK-005 | Relationships | Requests and service-owned artifacts can carry approved typed correlation, causation, and domain links. |
| ILK-006 | Artifacts | Services define artifact schemas and submit immutable, digest-bound content through requests. |
| ILK-007 | Decisions | Kernel security, administration, routing, and work decisions are explicit durable records. |
| ILK-008 | Audit | Security and governance actions produce append-only audit records. |
| ILK-009 | Events | Committed changes can produce typed events. |
| ILK-010 | Subscriptions | Services can declare the approved request, event, artifact, or work types they receive. |
| ILK-011 | Work claims | At most one service acting as a worker can hold the active claim for request-derived work. |
| ILK-012 | Idempotency | Retrying a request cannot accidentally perform it twice. |
| ILK-013 | Mediation | Services use request contracts; the hub proxies only fixed persistence operations and never caller-supplied SQL. |

## Capability invariants and acceptance criteria

### ILK-001: Identity

- Implementation: `src/kernel/identity.rs`
- Independent contract test: `tests/identity_contract.rs`

Invariants:

- Every non-public request or administrative action MUST be attributable to
  exactly one authenticated service or administrator and verified credential.
- Every running service instance MUST have a unique instance ID and freshly
  generated keypair; no private key may be shared with another instance or
  persisted outside its signing process.
- Identity IDs MUST remain stable even if display names or credentials change.
- Worker identities MUST be represented as a service role or profile.
- The kernel MUST NOT accept user credentials as kernel credentials.

Acceptance criteria:

- A request without a valid, fresh HTTP message signature from an enabled
  service is rejected before governed state is read or changed.
- A completed request can be traced back to the stable service ID, instance,
  and key that submitted it.
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
- Complete: separate default-deny PostgreSQL communication admission, a
  read-only kernel check, idempotent out-of-band administrative changes, direct
  mutation guards, and immutable old/new state history.
- Complete: governed HTTP middleware with strict single-value security headers,
  ordered signature, replay, and admission checks, typed caller context, and
  sanitized fail-closed responses.
- Pending: signed lease-renewal transport, ILK-002 Authority, and implemented
  governed subscription handlers behind the middleware.
- Pending: mediation and audit integration that attributes every completed
  request to that service and signing key.

See the [direct service protocol](direct-service-protocol.md) and
[ADR-0003](decisions/0003-direct-signed-service-rest.md).
Instance key and discovery lifecycle is specified by
[ADR-0005](decisions/0005-use-ephemeral-per-instance-service-keys.md).

### ILK-002: Authority

Invariants:

- The kernel MUST authorize a request before routing it, assigning work from
  it, or changing governed administrative state because of it.
- Authorization MUST default to denial when no applicable grant or policy
  permits the request.
- The decision MUST consider the authenticated source, destination, namespaced
  action, artifact type and schema version, permission-policy schema version,
  artifact or scope identifiers, and relevant administrative grants.
- A service MUST be able to define the action and permission vocabulary for
  artifacts in its namespace without requiring a new kernel release.
- A service-defined schema MUST be declarative data and MUST NOT contain
  executable code, SQL, database identifiers, or a mechanism for bypassing
  kernel mediation.
- Publishing a schema MUST NOT activate it or grant any identity permission.
- Only an authorized security administrator MAY approve, suspend, supersede,
  or retire a schema version and create, change, or revoke grants under it.
- A service MUST NOT authorize itself merely because it owns the artifact or
  permission-policy schema.
- The kernel MUST be the final enforcement point and MUST retain the exact
  schema versions, grants, and security context used for its decision.

Acceptance criteria:

- The same request is routed for an authorized source and denied for an
  unauthorized source without reaching the destination or changing governed
  state.
- Registering a schema does not make it active and does not grant its publisher
  permission.
- An active grant applies only to the schema version, action, artifact scope,
  source, destination, and validity period it declares.
- Unknown, inactive, superseded, malformed, or conflicting policy schemas fail
  closed.
- Security-relevant authorization outcomes identify the request, source,
  destination, action, artifact schema, policy schema, applicable grant, and
  administrator-controlled policy revision.

Implementation status:

- Pending: generic request authority, service-owned artifact and permission
  schema registration, administrative activation, grants, and decision audit.
- The existing signature, replay, and communication-admission gate is the
  required precondition and MUST remain ahead of this authority step.

### ILK-003: Requests

Invariants:

- Every request MUST have a stable ID unique within its source identity's
  namespace and MUST be permanently bound to one semantic request fingerprint.
- A request ID MUST NOT be reassigned to different content, action, artifact
  schema, permission schema, destination, or routing intent.
- The authenticated request envelope and content digest MUST become durable
  before the kernel reports acceptance.
- A request MUST identify its source, destination, namespaced action, artifact
  descriptor, permission-policy schema reference, correlation metadata, and
  creation time.
- Request acceptance MUST NOT imply authorization, delivery, work completion,
  or acceptance of the artifact by the destination service.
- Business-domain objects MUST remain service-owned artifacts rather than
  becoming generic kernel resource types.

Acceptance criteria:

- A successfully accepted request remains addressable after process restart.
- Retrying the same semantic request under the same request ID does not create
  another request.
- Reusing a request ID with a different destination, action, schema reference,
  artifact digest, or payload is rejected deterministically.
- The kernel can route a previously accepted request without interpreting its
  service-specific artifact content.

Implementation status:

- Partial foundation: the implemented replay layer permanently binds a source
  service and request ID to a semantic fingerprint.
- Pending: the complete durable Request envelope, destination, action, artifact
  descriptor, schema references, correlation relationships, and routing state.

### ILK-004: Versions

Invariants:

- An accepted request envelope and artifact digest MUST be immutable.
- Artifact schemas, permission-policy schemas, grants, routing decisions, work
  state, and other administrative records MUST be explicitly versioned or
  append-only; an accepted version MUST NOT be overwritten in place.
- Each schema version MUST identify its namespace owner, stable schema name,
  version, content digest, predecessor where applicable, publication time, and
  publishing service.
- Activation, suspension, supersession, and revocation MUST create separate
  administrator-attributed history rather than alter prior facts silently.
- Concurrent administration based on stale revisions MUST be rejected or
  explicitly reconciled.

Acceptance criteria:

- A decision can be reconstructed using the exact artifact schema, permission
  schema, grant, connection, and administrative revisions effective at that
  time.
- Publishing a new schema version leaves all earlier versions retrievable.
- Two administrators cannot silently replace each other's policy or grant
  changes.

### ILK-005: Relationships

Invariants:

- The kernel MUST define only universal request relationships such as
  correlation, causation, retry, response, routing, delivery, and work origin.
- Service-specific artifact relationship types MUST be namespaced and declared
  by an approved schema owned by the relevant service.
- Every stored link MUST identify its declared type, schema version, stable
  source, and stable target.
- The kernel MUST validate structural relationship metadata without assuming
  the business meaning of service-owned artifact links.
- Relationship history MUST be append-only or explicitly versioned.

Acceptance criteria:

- Requests can be queried by correlation, causation, response, delivery, and
  work-origin relationships.
- The kernel rejects an unknown, inactive, unnamespaced, or structurally
  invalid service-defined relationship type.
- Adding a new approved service relationship type requires no kernel code
  change.

### ILK-006: Artifacts

Invariants:

- Each artifact type and permission vocabulary MUST be owned by a stable service
  namespace and reference an approved, versioned schema.
- The kernel MUST treat artifact business content as opaque and MUST inspect
  only the bounded metadata required for security, schema selection, routing,
  storage mediation, and integrity verification.
- An accepted artifact's content digest, schema reference, owner, submitting
  service, request provenance, and storage reference MUST be immutable.
- An artifact correction MUST create a new artifact or request and use an
  approved relationship to the artifact it replaces or supplements.
- Artifact storage and retrieval MUST occur through typed kernel requests and
  fixed persistence adapters; services MUST NOT choose tables, columns,
  predicates, functions, or SQL.

Acceptance criteria:

- An artifact can be retrieved or proxied and verified against the exact digest
  and schema version originally accepted.
- An attempt to overwrite artifact content or change its schema reference is
  rejected.
- Two services can introduce unrelated artifact schemas without adding Rust
  business-domain types to the kernel.
- A schema owner cannot activate its own schema or grant itself access unless a
  separately authorized administrator explicitly does so.

Implementation status:

- Pending: service-owned artifact-schema and permission-policy-schema
  registration, administrator activation, immutable artifact descriptors, and
  fixed artifact storage/retrieval mediation.

### ILK-007: Decisions

Invariants:

- Kernel decisions MUST be limited to security, schema administration,
  connection admission, routing, delivery, subscription, work coordination,
  persistence mediation, and other hub responsibilities.
- A service-specific business decision SHOULD be represented as a service-owned
  artifact carried by a request rather than as a new kernel decision type.
- Every kernel decision MUST be a first-class durable record containing its
  type, outcome, responsible service or administrator, request ID, time,
  relevant security and schema revisions, and affected administrative objects.
- Reversal or supersession MUST create another decision linked to the earlier
  record.

Acceptance criteria:

- A caller can reconstruct why a request was admitted, denied, routed, paused,
  delivered, or assigned using recorded inputs and policy versions.
- Reversing an administrative or routing decision leaves the earlier decision
  available.
- Adding a service-specific business outcome does not require adding a kernel
  decision enum variant.

### ILK-008: Audit

Invariants:

- Security and governance actions MUST append an audit record in the same
  successful transaction as their governed state change.
- Audit records MUST NOT be updated or deleted through kernel contracts.
- Each record MUST include its event type, request ID where applicable, source
  and destination services, instance and key, namespaced action, artifact and
  permission schema versions, administrative revision, time, outcome, and
  correlation ID.
- Schema publication, activation, suspension, supersession, grant, revocation,
  connection, routing, replay, delivery, and work decisions MUST be auditable.

Acceptance criteria:

- A successful governed request or administrative change has a corresponding
  audit record.
- A rejected security-sensitive request or administrative action produces an
  audit record without a governed state change.
- Normal application credentials cannot update or delete audit history.

### ILK-009: Events

Invariants:

- An event MUST describe an already committed fact and MUST NOT announce a
  state change that can later roll back.
- Every event MUST have a stable event ID, declared type and schema version,
  occurrence time, and correlation ID.
- Kernel event types MUST describe hub facts such as request acceptance,
  authorization, routing, delivery, work, connection, and administration.
- Service-domain events MUST be namespaced and defined by an approved service
  schema rather than a hardcoded kernel business event enum.
- When a request promises an event, durable state and the event MUST be
  committed atomically.

Acceptance criteria:

- A failed or rolled-back request publishes no committed-change event.
- Consumers can distinguish event types and schema versions without inspecting
  an untyped payload.
- A newly approved service event schema can be routed without a kernel code
  change.

### ILK-010: Subscriptions

- Implementation: `src/kernel/subscriptions.rs`
- Independent contract test: `tests/subscription_contract.rs`

Invariants:

- A service MUST be able to create, inspect, and disable its subscriptions
  through kernel contracts.
- A subscription MUST identify its stable service owner and one or more
  approved request, event, artifact, or work types.
- Subscription changes MUST be authorized and audited.
- Delivery MUST obey the shared readiness/capacity health model without
  deleting or disabling durable subscription state.
- Every kernel instance MUST continuously discover reachable instances for
  active subscriptions and complete a fresh, mutual proof-of-possession
  handshake before delivering to an instance.

Acceptance criteria:

- A service receives or can retrieve only requests or events matching its
  active subscriptions, destination, approved schemas, and authorization scope.
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
- Every work item MUST originate from a durable request or an explicitly linked
  kernel coordination record; work MUST NOT create an unrelated business object
  model inside the kernel.
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

- Mutating requests MUST use their stable request ID as an idempotency key
  scoped to the authenticated source and semantic request fingerprint.
- Repeating the same request with the same key MUST return the original result
  and MUST NOT repeat its effects.
- Reusing a key with a materially different request MUST be rejected.
- Concurrent requests with the same key MUST converge on one committed result.

Acceptance criteria:

- Retrying after a lost response creates only one accepted request, mediated
  artifact write, administrative effect, audit change, and promised event.
- A key collision with a different payload returns a deterministic conflict.

### ILK-013: Mediation

Invariants:

- Services MUST submit business communication and work through authenticated
  Request contracts. Administrative state MUST use separately authenticated,
  explicitly typed administration contracts.
- No caller, including an administrative service, may submit SQL or database
  command fragments for the kernel to execute.
- Worker credentials MUST NOT grant direct write access to kernel-owned tables,
  event storage, or audit history.
- Kernel persistence adapters MUST use kernel-owned statement structure and
  bound values; caller-controlled identifiers or SQL structure are prohibited.
- Database proxying MUST mean that the hub performs an approved fixed storage
  or retrieval operation for a request; it MUST NOT mean a generic database,
  query, table, procedure, or expression proxy.
- The kernel MUST enforce identity, replay, admission, schema approval,
  authority, validation, idempotency, versioning, audit, and event rules at the
  mediation boundary.

Acceptance criteria:

- A service can submit, route, receive, and coordinate supported work using only
  Request and administration contracts.
- A service's runtime credentials cannot directly insert, update, or delete
  kernel-owned records.
- SQL-shaped operations are rejected before a repository or database adapter
  is called.
- Bypassing one contract cannot bypass the cross-cutting kernel invariants.

## Transaction boundary

For an accepted mutating request, the following effects MUST form one atomic
transaction where applicable:

1. validate identity, signature, freshness, replay, communication admission,
   request shape, schema activation, authority, and idempotency;
2. persist the immutable request envelope and semantic fingerprint;
3. apply fixed artifact-storage, routing, subscription, connection, or work
   coordination effects;
4. append required security, administration, and mediation audit records;
5. append promised kernel or approved service-schema events; and
6. persist the idempotent result.

The kernel reports success only after this transaction commits. Delivery of a
committed event to a subscriber MAY occur asynchronously.

## Minimum verification strategy

Each requirement MUST have automated tests at the lowest practical layer:

- unit tests for policy and state-transition rules;
- database integration tests for immutability, uniqueness, concurrency, and
  transaction rollback;
- contract tests for authentication, authorization, validation, and
  idempotency behavior; and
- end-to-end tests for request routing, event delivery, subscriptions, claim
  recovery, and mediated service workflows.

## Open design decisions

The requirements intentionally do not choose these implementation details:

- service-owned artifact-schema and permission-policy-schema formats;
- constrained policy evaluation language and scope matching rules;
- schema publication, administrator approval, and revocation workflow;
- universal request relationship representation and service-owned relationship
  schema format;
- artifact storage location and integrity mechanism;
- event transport and delivery guarantee;
- subscription cursor and replay semantics;
- claim lease duration and renewal protocol;
- idempotency retention period; and
- request payload/reference thresholds and storage-proxy limits.

Each consequential choice should be recorded as an ADR and linked back to the
affected `ILK-*` requirements.
