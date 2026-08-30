# Minimum viable kernel

> Status: Requirements draft  
> Last reviewed: 2026-08-30
> Owners: TODO

This document has two jobs. First, it defines the **minimum viable kernel
(v0.1.0)**: one complete, provable, governed-work vertical slice, narrow
enough to actually finish. Second, it preserves every other requirement the
kernel is expected to own eventually, explicitly classified so that scope
never expands by accident and nothing is silently deleted because it isn't
needed yet.

Every requirement below is classified into exactly one of:

- **MVP** — required to tag `v0.1.0`.
- **Post-MVP / Kernel 1.0** — a real, permanent kernel responsibility
  (it protects authority, correctness, durability, or replay semantics) that
  MUST NOT block `v0.1.0`.
- **External infrastructure** — optimization, placement, or policy-algorithm
  responsibility that belongs to a service other than the kernel
  (Taskmaster, Inquisitor, or a storage adapter).
- **Domain-owned** — business/artifact meaning that belongs to the services
  built on top of the kernel, never to the kernel itself.

The keywords **MUST**, **MUST NOT**, **SHOULD**, and **MAY** express
requirement strength throughout.

## Table of contents

1. [MVP objective](#1-mvp-objective)
2. [MVP architecture boundary](#2-mvp-architecture-boundary)
3. [MVP required capabilities](#3-mvp-required-capabilities)
4. [MVP end-to-end acceptance test](#4-mvp-end-to-end-acceptance-test)
5. [MVP failure/recovery tests](#5-mvp-failurerecovery-tests)
6. [Current implementation status](#6-current-implementation-status)
7. [Future Kernel / Kernel 1.0](#7-future-kernel-kernel-10)
8. [External service responsibilities](#8-external-service-responsibilities)
9. [Explicitly domain-owned responsibilities](#9-explicitly-domain-owned-responsibilities)
10. [Open design decisions](#10-open-design-decisions)

## 1. MVP objective

The boundary rule that organizes this whole document:

> The kernel owns authority and correctness. External infrastructure
> services own optimization and execution policy. Domain services own
> meaning.

Concretely, each party answers a different question:

- **The kernel** answers: *is this operation authenticated, authorized,
  valid, durable, eligible, unique, replay-safe, and safely ownable?*
- **Taskmaster** (external scheduler) answers: *of the work the kernel says
  may run, what should run next and where?*
- **Inquisitor** (external policy evaluator) answers: *given this
  kernel-supplied fact bundle and policy version, does policy evaluate to
  allow or deny?*
- **Domain services** answer: *what does this artifact/request mean, and
  what business action should be performed?*

The minimum viable kernel (`v0.1.0`) exists once the kernel can prove one
complete governed-work vertical slice, end to end, against a real
PostgreSQL backend:

1. An authenticated service submits a signed Request.
2. The kernel authenticates the service.
3. The kernel performs communication admission/replay protection.
4. The kernel constructs trusted authority facts and obtains an allow/deny
   verdict from the external stateless policy evaluator.
5. The kernel records and enforces that authority decision.
6. The accepted Request is durably persisted in PostgreSQL.
7. A basic active subscription can match the Request.
8. The kernel materializes a durable route.
9. An external scheduler can query eligible work.
10. The scheduler proposes a worker/route claim.
11. The kernel atomically arbitrates the claim using lease/fencing
    semantics.
12. The worker can complete the work through the kernel.
13. The resulting state and required audit evidence are durable.
14. Restart/retry/failure cannot silently duplicate, lose, or incorrectly
    complete the work.

Section 4 maps every step above onto the concrete kernel mechanism (and
test) that proves it. Section 5 lists the specific failure/recovery proofs
`v0.1.0` also requires. Section 6 is the short, current answer to "what
exactly is left before tagging `v0.1.0`."

A capability that is real, useful, and even partially built is not
automatically MVP. It is MVP only if the vertical slice above cannot be
proven without it. Everything else is preserved — never deleted — under
Sections 7 through 9, classified by who should own it long-term.

## 2. MVP architecture boundary

This section is the kernel's standing architecture: the object model,
storage model, and routing ledger that both the MVP slice and every
deferred capability build on. None of it is deleted or weakened by MVP
scoping; MVP simply exercises a subset of it (marked inline below).

### Terms

- **Service principal** — a backend service admitted to the kernel with a
  stable identity and one or more registered public keys.
- **Worker** — a service principal that consumes events or claims work for
  processing.
- **Scheduler** (Taskmaster) — an ordinary, non-privileged service principal
  that reads the kernel's eligible-route query and decides which eligible
  route runs next and on which worker or node. It owns optimization policy
  (ordering, priority, affinity, resource-class placement, capacity,
  backpressure timing, retry timing); it holds no elevated database access
  and cannot bypass claim arbitration. The kernel is its only source of
  registered request, route, health/capacity-relay, and claim state — a
  scheduler never receives that state from a worker directly or from any
  other event source. See
  [ADR-0011](decisions/0011-move-scheduling-policy-outside-the-kernel.md)
  and [Section 8](#8-external-service-responsibilities).
- **Policy evaluator** (Inquisitor) — an ordinary, non-privileged service
  principal that holds no authorization data of its own. The kernel sends
  it a fact bundle (source, action, schema versions, scope/artifact
  identifiers, grants, and destination when applicable) and it returns an
  allow/deny verdict plus the policy bundle/version it evaluated. The
  kernel alone owns the grants, schemas, and audit trail; an unreachable or
  erroring evaluator is denial, never implicit allow. See
  [ADR-0013](decisions/0013-external-stateless-policy-evaluator-for-authority.md)
  and [Section 8](#8-external-service-responsibilities).
- **External user subject** — optional provenance asserted by an
  authenticated service; it is not a kernel principal or credential.
- **Request** — the immutable, signed, durable communication envelope
  submitted by one service. It declares intent and matching metadata but no
  concrete destination service.
- **Request route** — a kernel-owned administrative record binding one
  request to either one exclusive consumer group or one inclusive
  subscription destination. It carries that target's independent
  routing/work state and exposes no destination discovery information to
  the source service. (MVP implements the inclusive case only; see
  [ILK-003](#ilk-003-requests) and [ILK-010](#ilk-010-subscriptions).)
- **Exclusive subscription** — a competing-consumer subscription for which
  one request/consumer-group route may be assigned to only one eligible
  service at a time and may be reassigned after a fenced lease expires.
  **Post-MVP / Kernel 1.0** — see [ILK-010](#ilk-010-subscriptions).
- **Inclusive subscription** — a fan-out subscription for which every
  matching stable destination service owns an independent request route
  and completion. **MVP.**
- **Action name** — a service-owned, namespaced action declared by an
  approved artifact and permission-policy schema; it is not a kernel-wide
  enum.
- **Artifact** — service-owned content carried by reference or value in a
  request. The kernel treats its business content as opaque except for
  approved schema metadata, routing fields, content length, and content
  digest. **MVP carries only the schema version reference required for
  authority (ILK-002); actual artifact content mediation is Post-MVP — see
  [ILK-006](#ilk-006-artifacts).**
- **Artifact schema** — a namespaced, versioned contract defined by the
  service that owns an artifact type. **MVP** (publication already
  implemented under ILK-002).
- **Permission-policy schema** — a namespaced, versioned declaration from a
  service describing the actions and permission fields meaningful for its
  artifacts. Administrators, not the defining service, control activation
  and grants under that schema. **MVP.**
- **Administrative object** — kernel-owned security, connection, schema
  registration, policy activation, grant, routing, subscription, work,
  audit, replay, or idempotency state.
- **Kernel contract** — an authenticated command or query interface owned
  by the kernel.

### Kernel object boundary

The kernel MUST NOT grow a universal business-resource model. A request MAY
refer to service-owned artifacts, but the kernel MUST NOT require Rust
types for every invoice, document, model, medical record, or future
service object. The kernel's eventual full object contract has a governed
request carry or resolve at least:

- a stable request ID — **MVP**;
- authenticated source service, instance, and key IDs — **MVP**;
- a namespaced action — **MVP**;
- artifact type, schema name, schema version, and schema owner — **MVP**
  (schema *reference* only; see ILK-006 for content mediation);
- permission-policy schema name, version, and owner — **MVP**;
- artifact ID or payload reference plus content digest — **Post-MVP**, not
  carried by the request today (see [ILK-006](#ilk-006-artifacts));
- correlation and optional causation IDs — **Post-MVP**, not carried by the
  request today (see [ILK-005](#ilk-005-relationships)); and
- creation, expiry, replay, and idempotency metadata — **MVP** (creation,
  replay, and idempotency; explicit request expiry is Post-MVP).

A service MAY publish new artifact and permission-policy schemas in its own
namespace. Publication MUST NOT activate a schema, authorize the publisher,
or create a grant. A security administrator MUST explicitly approve schema
versions and bind identities to permissions. The kernel MUST make and
retain the final allow-or-deny result. **MVP** — implemented in full.

### Authoritative state boundary

**MVP** — this entire boundary is load-bearing for the vertical slice and
is already true by construction:

- Every recoverable kernel fact MUST be stored in PostgreSQL before success
  is reported or an externally visible governed effect is released.
- Fresh kernel processes MUST reconstruct all pending work, cursors,
  leases, and decisions exclusively from PostgreSQL.
- Memory caches MUST be disposable and MUST NOT authorize, route, assign,
  claim, complete, acknowledge, or advance work without a current
  PostgreSQL transaction.
- Local files, container filesystems, Kubernetes objects, persistent
  volumes, and message brokers MUST NOT be authoritative kernel state.
- The ephemeral private signing key is intentionally not recoverable
  state. A restarted instance creates a new identity/key pair and
  registers its public record in PostgreSQL before becoming eligible.
- PostgreSQL unavailability MUST make the kernel unready and fail closed
  for governed mutations, security-sensitive reads, request acceptance,
  replay, delivery, and work coordination.
- In-memory repositories MAY exist only as isolated test doubles and MUST
  NOT be used in production wiring.

### Routing ledger

The kernel separates immutable intent, interest, destination progress, and
exclusive ownership:

| Record | Identity and purpose | Multiplicity | Scope |
| --- | --- | --- | --- |
| Request | Source-authenticated intent and matching metadata | One accepted record per source/request ID | MVP |
| Subscription | A stable service's declared interest and wakeup cursor | Zero or more matches per request | MVP (inclusive only; cursor is a simple active-set match, not a durable replay cursor — see ILK-010) |
| Request route | Deduplication and completion boundary for an exclusive group or inclusive destination | At most one per request/group or request/destination | MVP (inclusive only) |
| Route transition | Append-only evidence of ready, claimed, completed, paused, or terminal progress, including the applicable subscription | Many per route | Post-MVP as a dedicated ledger — MVP gets equivalent minimum evidence from the route and work-claim tables' own append-only status history, which already satisfies the vertical slice's audit acceptance criteria (see [ILK-008](#ilk-008-audit)) |
| Work claim | Exclusive lease naming the worker currently handling a route | At most one active claim per route; history retained | MVP |

An accepted request with no matching subscription is **unrouted**, not
failed. When a subscription matches, the kernel idempotently creates or
wakes the request route for that stable destination. The kernel's
next-work query uses active subscription state and its durable cursor to
expose which incomplete routes are eligible; it does not select which one
runs next or on which worker — that policy belongs to an external
scheduler service (see
[ADR-0011](decisions/0011-move-scheduling-policy-outside-the-kernel.md)).
The work-claim contract then atomically arbitrates whichever claim a
scheduler requests: authorized, still eligible, unclaimed, and
fencing-current, or rejected. A completion is scoped to that route and
records the subscription and worker responsible. It does not complete the
parent request for any other destination.

### Transaction boundary

**MVP** — for an accepted mutating request, the following effects MUST
form one atomic transaction where applicable:

1. validate identity, signature, freshness, replay, communication
   admission, request shape, schema activation, authority, and
   idempotency;
2. persist the immutable request envelope and semantic fingerprint;
3. apply fixed artifact-storage, routing, subscription, connection, or
   work coordination effects;
4. append required security, administration, and mediation audit records;
5. append promised kernel or approved service-schema events (Post-MVP —
   see [ILK-009](#ilk-009-events); no step of the MVP vertical slice
   promises an event yet); and
6. persist the idempotent result.

The kernel reports success only after this transaction commits. Delivery
of a committed event to a subscriber MAY occur asynchronously.

## 3. MVP required capabilities

Every `ILK-*` identifier from the original requirements draft is preserved.
Each capability below is tagged **MVP**, **Split** (part of it gates
`v0.1.0`, part is Kernel 1.0), or **Post-MVP / Kernel 1.0** (the whole
capability is deferred — its full text lives in
[Section 7](#7-future-kernel-kernel-10), not repeated here).

| ID | Capability | Scope for v0.1.0 |
| --- | --- | --- |
| ILK-001 | Identity | **MVP** |
| ILK-002 | Authority | **Split** — request-acceptance authority is MVP; per-route re-authorization and schema-lifecycle administration UI are Kernel 1.0 |
| ILK-003 | Requests | **Split** — immutable durable requests and inclusive-only route materialization are MVP; correlation, exclusive groups, route history, and backlog matching are Kernel 1.0 |
| ILK-004 | Versions | **MVP** (the append-only/immutability invariant itself; administrative lifecycle workflow is external — see ILK-002) |
| ILK-005 | Relationships | **Post-MVP / Kernel 1.0** — unimplemented, not required by the vertical slice |
| ILK-006 | Artifacts | **Post-MVP / Kernel 1.0** + External storage — unimplemented, not required by the vertical slice |
| ILK-007 | Decisions | **Split** — the authority decision record is MVP; a generalized Decision type spanning routing/pause/assignment is Kernel 1.0 |
| ILK-008 | Audit | **MVP** (minimum evidence to reconstruct the vertical slice already exists per-capability; a unified audit log is Kernel 1.0) |
| ILK-009 | Events | **Post-MVP / Kernel 1.0** — unimplemented, not required by the vertical slice |
| ILK-010 | Subscriptions | **Split** — inclusive create/list/disable/materialize is MVP; exclusive groups, `all_of` selectors, backlog matching, cursors, route history are Kernel 1.0 |
| ILK-011 | Work claims | **Split** — claim/renew/release/complete with fencing is MVP (done); the eligible-route query is MVP (not yet done); administrative forced revocation is Kernel 1.0 |
| ILK-012 | Idempotency | **Split** — request-level idempotency (via ILK-003) is MVP; idempotency for artifact writes/events is Kernel 1.0, blocked on ILK-006/009 |
| ILK-013 | Mediation | **MVP** — structural invariant, already true by construction |

### ILK-001: Identity

**Scope: MVP** (in full).

- Implementation: `src/kernel/identity.rs`
- Independent contract test: `tests/identity_contract.rs`

Invariants:

- Every non-public request or administrative action MUST be attributable
  to exactly one authenticated service or administrator and verified
  credential.
- Every running service instance MUST have a unique instance ID and
  freshly generated keypair; no private key may be shared with another
  instance or persisted outside its signing process.
- Identity IDs MUST remain stable even if display names or credentials
  change.
- Worker identities MUST be represented as a service role or profile.
- The kernel MUST NOT accept user credentials as kernel credentials.

Acceptance criteria:

- A request without a valid, fresh HTTP message signature from an enabled
  service is rejected before governed state is read or changed.
- A completed request can be traced back to the stable service ID,
  instance, and key that submitted it.
- Restarting a service process creates a new instance ID and key and
  requires a new proof-of-possession handshake.

Implementation status:

- Complete: stable UUID IDs, service/worker distinction, active and
  disabled lifecycle, display-name validation, repository contract, and
  independently testable service behavior.
- Complete: PostgreSQL identity repository, schema constraints, migration,
  and restart-durability integration test.
- Complete: the domain and database schema reject human identities and
  accept only service and worker principals.
- Complete: unique per-process instance and key IDs, ephemeral Ed25519
  signing keys, public verification records, and process-wide application
  wiring.
- Complete: kernel-owned PostgreSQL public-key registration, immutable key
  records, bounded compare-and-set leases, revocation, and append-only
  registry audit storage behind a typed repository contract.
- Complete: authenticated initial enrollment, kernel-to-subscriber
  discovery handshakes, and fixed-profile Ed25519 HTTP Message Signature
  verification covering the request method, target URI, content, stable
  service, instance, key, and request ID with bounded signature
  timestamps.
- Complete: atomic PostgreSQL nonce-digest consumption, permanent
  service/request-ID fingerprint binding, safe-retry classification,
  conflict rejection, and append-only accepted/rejected replay audit.
- Complete: separate default-deny PostgreSQL communication admission, a
  read-only kernel check, idempotent out-of-band administrative changes,
  direct mutation guards, and immutable old/new state history.
- Complete: governed HTTP middleware with strict single-value security
  headers, ordered signature, replay, and admission checks, typed caller
  context, and sanitized fail-closed responses.
- Complete: ILK-002 authority and implemented governed subscription/
  request/route/claim handlers behind the middleware (was "Pending" in an
  earlier revision).
- Post-MVP / Kernel 1.0: signed lease-renewal transport; correctness under
  multiple kernel replicas for `GET /v1/kernel-identity` (see
  [Section 7](#7-future-kernel-kernel-10)).

See the [direct service protocol](direct-service-protocol.md) and
[ADR-0003](decisions/0003-direct-signed-service-rest.md).
Instance key and discovery lifecycle is specified by
[ADR-0005](decisions/0005-use-ephemeral-per-instance-service-keys.md).

### ILK-002: Authority

**Scope: Split.**

**MVP** covers everything needed to authorize step 4–5 of the vertical
slice: a real allow/deny decision from the external evaluator for request
acceptance, fail-closed on denial or evaluator failure, and durable,
version-pinned decision recording.

**Post-MVP / Kernel 1.0**: a second, destination-scoped authority decision
that separately re-authorizes a route before it is exposed, claimed, or
delivered (the domain primitive, `PolicyFacts::for_route`, already exists
and is contract-tested; it is simply not yet wired into any HTTP route),
and administrator-facing schema-activation workflow/UI (the underlying
`set_authority_schema_status` function is Postgres-only today).

Invariants:

- **MVP** — The kernel MUST authorize a request before routing it,
  assigning work from it, or changing governed administrative state
  because of it.
- **MVP** — Authorization MUST default to denial when no applicable grant
  or policy permits the request.
- **MVP** — Request-acceptance authority MUST consider the authenticated
  source, namespaced action, artifact type and schema version,
  permission-policy schema version, artifact or scope identifiers, and
  relevant administrative grants.
- **Post-MVP / Kernel 1.0** — Route authority MUST separately consider the
  kernel-derived destination, matching subscription, and current
  destination-scoped grants before the route is exposed, claimed, or
  delivered. MVP instead enforces route/claim ownership structurally (the
  caller's service must match the route's own destination — see
  [ILK-011](#ilk-011-work-claims)), which is sufficient for one
  inclusive-only vertical slice but is not a full second policy decision.
- **MVP** — A service MUST be able to define the action and permission
  vocabulary for artifacts in its namespace without requiring a new
  kernel release.
- **MVP** — A service-defined schema MUST be declarative data and MUST NOT
  contain executable code, SQL, database identifiers, or a mechanism for
  bypassing kernel mediation.
- **MVP** — Publishing a schema MUST NOT activate it or grant any identity
  permission.
- **MVP** (mechanism) / **Post-MVP** (administrative UI) — Only an
  authorized security administrator MAY approve, suspend, supersede, or
  retire a schema version and create, change, or revoke grants under it.
- **MVP** — A service MUST NOT authorize itself merely because it owns the
  artifact or permission-policy schema.
- **MVP** — The kernel MUST be the final enforcement point and MUST retain
  the exact schema versions, grants, and security context used for its
  decision. The kernel MAY delegate the allow/deny *algorithm* to an
  external, stateless policy evaluator that stores no data of its own,
  provided the kernel alone owns the grants, schemas, and facts the
  evaluator is given, and alone records the verdict (see
  [ADR-0013](decisions/0013-external-stateless-policy-evaluator-for-authority.md)).
- **MVP** — An unreachable, erroring, or malformed-response policy
  evaluator MUST be treated as denial, never as an implicit allow.
- **MVP** — A recorded authority verdict MUST be pinned to the policy
  bundle/version evaluated at that time; a later policy change MUST NOT
  retroactively alter an earlier accepted request's or materialized
  route's authorization.
- **Split** — Request-acceptance authority and route authority are
  distinct decisions, each independently pinned, using one shared
  evaluation contract with different fact bundles rather than two separate
  integrations. The shared contract and both fact-bundle constructors are
  MVP-complete; only the second decision's live wiring into route
  exposure/claiming is Post-MVP.

Acceptance criteria:

- The same request is routed for an authorized source and denied for an
  unauthorized source without reaching the destination or changing
  governed state. **MVP.**
- Registering a schema does not make it active and does not grant its
  publisher permission. **MVP.**
- An active grant applies only to the schema version, action, artifact
  scope, source, optional route destination, and validity period it
  declares. **MVP.**
- Unknown, inactive, superseded, malformed, or conflicting policy schemas
  fail closed. **MVP.**
- Security-relevant authorization outcomes identify the request, source,
  action, artifact schema, policy schema, applicable grant, and
  administrator-controlled policy revision, plus the route destination and
  subscription when the decision is destination-specific. **MVP** for the
  request-acceptance case; the destination-specific case is Post-MVP,
  pending the route-authority wiring above.

Implementation status:

- Complete: the typed domain contract — `Grant`, `Scope`,
  `PolicyBundleVersion`, `PolicyFacts` (shared by both decision points,
  including `for_request_acceptance` and `for_route`), `Verdict`, and the
  pinned `AuthorityDecision` — plus the `AuthorityRepository` and
  `PolicyEvaluator` trait boundary and `AuthorityService::authorize`, with
  an independently runnable contract test covering default-deny, grant
  matching and expiry, wildcard scope, fail-closed evaluator handling, and
  that request-acceptance and route decisions never share a grant.
- Complete: PostgreSQL-backed, append-only grant storage read through
  `PostgresAuthorityRepository`, and an idempotent, conflict-detecting,
  security-definer `create_authority_grant` administration function that
  the Rust kernel never calls directly — grants are administered
  out-of-band, exactly as communication admission already is.
- Complete: the typed schema domain contract — `SchemaKind` (artifact vs.
  permission-policy, independent namespaces even under the same name),
  `SchemaName`, `ContentDigest`, and the immutable `SchemaVersion` chained
  to its predecessor — plus `SchemaRepository`/`SchemaService::publish`,
  which any authenticated service may call for names it owns to register a
  new version without activating it, and which rejects a different
  service publishing under an already-claimed name
  (`AuthorityError::SchemaNamespaceConflict`). `SchemaStatus` (Published,
  Active, Suspended, Superseded, Retired) exists as a value type read from
  `SchemaRecord`.
- Complete: PostgreSQL-backed schema storage.
  `publish_authority_schema_version` atomically locks the current latest
  version for a `(kind, name)`, checks owner consistency, and assigns the
  next version and predecessor link; it is called directly by
  `PostgresAuthorityRepository` on behalf of any authenticated service,
  unlike grant creation. `set_authority_schema_status` is the
  administrator-only, idempotent, terminal-state-respecting counterpart to
  `create_authority_grant`, moving a schema through Published →
  Active/Retired → Suspended/Superseded/Retired with append-only status
  audit; superseded and retired are terminal and the Rust kernel never
  calls this function directly.
- Complete: durable decision pinning. `AuthorityService::authorize` mints a
  `DecisionId` and calls a new `AuthorityDecisionRecorder` dependency
  before ever returning a decision; recording failure fails `authorize`
  itself rather than returning an unrecorded decision, the same
  fail-closed posture used everywhere else in the kernel.
  `PostgresAuthorityRepository` implements the recorder with a plain
  append-only insert into `authority_decisions` — kernel bookkeeping, not
  administration, so there is no out-of-band function gating it, unlike
  grants and schema status.
- Complete: schema version references are mandatory on `PolicyFacts` and
  `Grant`, not optional. `SchemaVersionRefs` bundles one artifact schema
  version and one permission-policy schema version; `Grant::permits`
  requires an exact match on both, so reactivating, retiring, or
  superseding a schema version never silently extends or breaks a grant
  pinned to a specific version. PostgreSQL enforces the same requirement
  structurally: both `authority_grants` and `authority_decisions` carry
  mandatory, foreign-key-checked columns for both schema versions, and
  `create_authority_grant` additionally checks that each referenced
  version is the expected kind (artifact vs. permission-policy) before
  accepting a grant.
- Complete: the `GET /v1/kernel-identity` route publishing this process's
  current public signing key, unauthenticated by design, so a future
  caller (the policy evaluator, or the handshake reconciler's outbound
  transport) can verify a kernel-signed message without static
  configuration that breaks on every kernel restart (ADR-0014). Correct
  behavior behind multiple kernel replicas remains a Kernel 1.0 follow-up
  (see [Section 7](#7-future-kernel-kernel-10)).
- The outbound signed-call machinery itself now exists outside the kernel:
  `infernal-client-rs` ([ADR-0012](decisions/0012-rust-first-client-sdk-family-over-signed-rest.md))
  implements the signing side of ADR-0003 and verifying a kernel identity
  against `GET /v1/kernel-identity`, and this repository's own test suite
  proves a request it signs is accepted by the kernel's real, unmodified
  `ServiceRequestVerifier`, and — the mechanism a reference policy
  evaluator will actually run — that a request the kernel signs with its
  own `InstanceCredential` via `sign_with` is correctly accepted by
  `infernal-client-rs`'s own `verify_incoming`
  (`tests/infernal_client_rs_wire_compatibility.rs`). `infernal-client-rs`
  is now a runtime dependency (git, pinned to a commit), not only a
  dev-dependency.
- Complete: `HttpPolicyEvaluator` (`src/infrastructure/http_policy_evaluator.rs`)
  implements `PolicyEvaluator` as a real signed HTTP call, using
  `infernal-client-rs`'s `sign_with` to sign with the kernel's own
  long-lived instance credential — the same key `GET /v1/kernel-identity`
  publishes — rather than a second key nothing would recognize. Any
  non-2xx status, network failure, or malformed/unrecognized response body
  is surfaced as `AuthorityError::Evaluator`, which `AuthorityService`
  already turns into a fail-closed denial. Colocated tests verify the
  signed request independently against the kernel's own
  `ServiceRequestVerifier` and verify response parsing without any network
  dependency. Per [ADR-0013](decisions/0013-external-stateless-policy-evaluator-for-authority.md)'s
  refined design, only the kernel's outbound call is signed at the
  application layer; the evaluator's response is trusted over the same
  HTTPS connection the kernel itself opened, not by a second signature.
- Complete: a reference external policy evaluator service,
  [`infernal-inquisitor-simple`](https://github.com/BenjaminGrandstaff/infernal-inquisitor-simple),
  exists to actually call — it verifies the kernel's signed request
  against the kernel's self-published identity using
  `infernal-client-rs`'s own `verify_incoming`, then applies the same
  "allow if a grant matched" shape of policy `HttpPolicyEvaluator` expects
  a verdict for. Its own test suite proves this against a live (if fake)
  kernel-identity HTTP server, not just in-process values.
- Complete: `Application::authority_service` builds an
  `HttpPolicyEvaluator`-backed `AuthorityService` on demand (env-configured
  `POLICY_EVALUATOR_AUTHORITY`/`POLICY_EVALUATOR_ID`), and ILK-010's
  `POST /v1/subscriptions` and `DELETE /v1/subscriptions/{id}` handlers,
  and ILK-003's `POST /v1/requests` handler, call it before mutating —
  `GET` reads do not, since reading the caller's own data does not itself
  change governed administrative state. An unconfigured or unreachable
  evaluator, or a deny verdict, fails closed (`503`/`403`), never an
  implicit allow.
- Complete: `POST /v1/authority/schemas` exposes `SchemaService::publish`
  over the governed HTTP boundary (`src/http/schema_dto.rs`) — any
  authenticated caller may publish a schema version under its own verified
  identity for a name it owns; a different service already owning that
  `(kind, name)` is rejected as a sanitized `409`. Publishing alone never
  activates a schema or grants its publisher permission (ILK-002's own
  wording), so this route requires no ILK-002 authority decision, only
  authentication.
- Post-MVP / Kernel 1.0: wiring `PolicyFacts::for_route` into an actual
  destination-scoped re-authorization at route exposure or claim time
  (today, ownership matching stands in for it — see ILK-011); and
  administrator-driven schema activation exposed as a kernel contract
  rather than only a Postgres function (`set_authority_schema_status`).
- Out-of-band provisioning required for a real (non-`503`, non-default-deny)
  decision in production — an `identities` row and enrollment binding for
  each calling service, an `identities` row for whatever
  `POLICY_EVALUATOR_ID` names, and at least one grant — is deployment
  configuration, not missing code; it uses the same administrative pattern
  grants and schema status already use.
  `tests/postgres_authority_repository.rs`'s ignored integration tests
  already exercise the identity-then-schema-then-decision path end to end
  against a real Postgres backend.
- The existing signature, replay, and communication-admission gate is the
  required precondition and MUST remain ahead of this authority step.

### ILK-003: Requests

**Scope: Split.**

**MVP**: the immutable, durable request itself, idempotent acceptance under
retry, rejection of ID reuse for different content, and idempotent
materialization of inclusive routes for actively-matching subscriptions.

**Post-MVP / Kernel 1.0**: correlation/causation relationships (full
realization is [ILK-005](#ilk-005-relationships)), exclusive-group routes
and consumer-group semantics, append-only route transition history, and
backlog matching (a subscription committed *after* a request does not yet
retroactively see it — MVP's vertical slice assumes the subscription is
already active when the request is submitted).

Invariants:

- **MVP** — Every request MUST have a stable ID unique within its source
  identity's namespace and MUST be permanently bound to one semantic
  request fingerprint.
- **MVP** — A request ID MUST NOT be reassigned to different content,
  action, artifact schema, permission schema, or routing intent.
- **MVP** — The authenticated request envelope and content digest MUST
  become durable before the kernel reports acceptance.
- **MVP** — A request MUST identify its source, namespaced action,
  artifact descriptor, permission-policy schema reference, and creation
  time. (Correlation metadata is Post-MVP — see ILK-005.)
- **MVP** — A request MUST NOT name or expose a concrete destination
  service. The kernel derives destination routes only from authorized
  matching subscriptions.
- **MVP** — Request acceptance and durable storage MUST NOT depend on a
  matching active subscription, reachable destination instance, current
  health, or available delivery capacity.
- **MVP** — A request without an eligible matching subscriber MUST remain
  durably unrouted; it MUST NOT be rejected or silently discarded merely
  because no subscriber exists yet.
- **MVP** (inclusive) / **Post-MVP** (exclusive) — A matching subscription
  MUST materialize at most one exclusive route for the request/consumer
  group or one inclusive route for the request/stable destination. Those
  unique keys MUST make repeated scans, retries, and subscription wakeups
  idempotent.
- **MVP** — One request MAY have routes to many destination services.
  **Post-MVP** — every route MUST have its own append-only transition
  history (today a route has state but not a dedicated transition-history
  ledger; see the routing-ledger table in Section 2).
- **MVP** — Completing one route MUST record the subscription and
  destination for which it completed and MUST NOT complete, cancel, or
  advance another route.
- **MVP** — The current worker MUST be represented by the route's active
  work claim; completed and expired claims MUST remain available to show
  who worked or attempted the route.
- **MVP** — A source MUST NOT receive destination discovery information.
  The kernel owns subscriber discovery, instance selection, handshake, and
  delivery.
- **MVP** — Request acceptance MUST NOT imply authorization, delivery,
  work completion, or acceptance of the artifact by the destination
  service.
- **MVP** — Business-domain objects MUST remain service-owned artifacts
  rather than becoming generic kernel resource types.

Acceptance criteria:

- A successfully accepted request remains addressable after process
  restart. **MVP.**
- Retrying the same semantic request under the same request ID does not
  create another request. **MVP.**
- Reusing a request ID with a different action, schema reference,
  artifact digest, or payload is rejected deterministically. **MVP.**
- The kernel can route a previously accepted request without interpreting
  its service-specific artifact content. **MVP.**
- A request accepted before its matching subscription exists becomes
  eligible for delivery after that subscription is committed, without
  source resubmission. **Post-MVP** (backlog matching — not implemented;
  MVP requires the subscription to already be active at submission time).
- A subscription-creation race cannot lose a matching pending request or
  create more than one accepted request record. **Post-MVP**, coupled to
  backlog matching above.
- Two matching destination services produce two independently tracked
  routes; completing either route leaves the other route eligible for
  work. **MVP** (proven for inclusive routes today).
- Replaying backlog scans or wakeups cannot create duplicate work for an
  existing exclusive-group or inclusive-destination route. **MVP** for
  inclusive; **Post-MVP** for exclusive-group.

Implementation status:

- Complete: the typed immutable core records a stable Request ID, source
  service, and validated namespaced action without a concrete
  destination.
- Complete: the core contract has an independently runnable test and
  exposes no field mutation operations.
- Complete: the artifact descriptor and permission-policy schema reference
  this invariant list requires. `Request` carries `scope`/`schema_versions`
  using the same `authority::Scope`/`SchemaVersionRefs` types ILK-002
  evaluates against (`PolicyFacts::for_request_acceptance`), so there is
  one validated representation of each, not a parallel one that could
  drift. `Request::fingerprint()` deterministically hashes all four
  immutable fields (source, action, scope, schema versions),
  length-prefixed so no combination of values can collide by
  concatenation.
- Complete: atomic PostgreSQL acceptance scoped to `(source_service_id,
  request_id)`, safe-retry classification, conflict rejection on
  rebinding, and append-only acceptance audit surviving process restart.
  Both schema version columns are mandatory, foreign-keyed to
  `authority_schema_versions`, and a foreign-key violation there is now
  reported as `RequestError::UnknownSchemaVersion` (matched by Postgres
  constraint name), distinct from `UnknownSource` — conflating the two
  would misreport a valid caller as unauthenticated.
- Complete: authenticated-envelope construction. `POST /v1/requests`
  (`src/http/request_dto.rs`) builds the request from the caller's own
  verified identity and, notably, the *signed envelope's own*
  `infernal-request-id` (`VerifiedServiceRequest::request_id`) as the
  durable ILK-003 request ID — not a body field, and not freshly minted
  per call. The caller already controls that value and retries a lost
  response with it unchanged, so reusing it is what makes submission
  idempotent under retry without a second, redundant identifier.
  Submission is authorized by a real ILK-002 decision built from the
  request's own action, scope, and schema versions. `GET /v1/requests/{id}`
  reads back only the caller's own accepted request; another service's
  request looks identical to one that does not exist.
- Complete (first slice — this is the MVP-required piece): `Route`,
  `RouteRepository`, and `RouteService` (`src/kernel/requests.rs`) — an
  accepted request's independent, idempotently-materialized destinations,
  one per matching active inclusive subscription (ILK-010). No delivery
  state, transition history, or work claim exists on a route itself — it
  records only that a destination is eligible; a route's own claim history
  (ILK-011) is what currently stands in for transition evidence.
- Post-MVP / Kernel 1.0: correlation relationships, exclusive-group routes
  and their consumer-group semantics, route transition history, and
  subscription-triggered backlog routing (a subscription committed after a
  request does not yet retroactively see it).

### ILK-004: Versions

**Scope: MVP** — the append-only/immutability invariant is load-bearing
for the vertical slice (schema version pinning, decision pinning) and is
already true by construction wherever it is exercised. Administrative
lifecycle *workflow* (as opposed to the underlying immutability) is
external tooling — see [ILK-002](#ilk-002-authority).

Invariants:

- An accepted request envelope and artifact digest MUST be immutable.
- Artifact schemas, permission-policy schemas, grants, routing decisions,
  work state, and other administrative records MUST be explicitly
  versioned or append-only; an accepted version MUST NOT be overwritten in
  place.
- Each schema version MUST identify its namespace owner, stable schema
  name, version, content digest, predecessor where applicable, publication
  time, and publishing service.
- Activation, suspension, supersession, and revocation MUST create
  separate administrator-attributed history rather than alter prior facts
  silently.
- Concurrent administration based on stale revisions MUST be rejected or
  explicitly reconciled.

Acceptance criteria:

- A decision can be reconstructed using the exact artifact schema,
  permission schema, grant, connection, and administrative revisions
  effective at that time.
- Publishing a new schema version leaves all earlier versions retrievable.
- Two administrators cannot silently replace each other's policy or grant
  changes.

This capability has no separate implementation-status section because it
is not built as standalone code — it is a structural property enforced by
ILK-002's and ILK-003's own append-only tables and immutable types. See
their status sections above.

### ILK-005: Relationships

**Scope: Post-MVP / Kernel 1.0 — the entire capability.** Nothing here is
implemented, and the MVP vertical slice does not require it (no step needs
correlation/causation querying). Full text preserved in
[Section 7](#7-future-kernel-kernel-10).

### ILK-006: Artifacts

**Scope: Post-MVP / Kernel 1.0 + External infrastructure — the entire
capability.** `Request` does not carry artifact content, an artifact ID, or
a payload reference today — only the schema *version reference* used for
authority (which is ILK-002's responsibility, already MVP-complete). Actual
artifact content mediation is not required by the vertical slice. Full
text preserved in [Section 7](#7-future-kernel-kernel-10); the physical
storage question is discussed in
[Section 8](#8-external-service-responsibilities).

### ILK-007: Decisions

**Scope: Split.**

**MVP**: the authority decision is the one kernel decision type the
vertical slice actually needs, and it already satisfies the shape this
capability describes (durable record, type, outcome, responsible party,
request ID, time, security/schema revisions — see `AuthorityDecision` and
`AuthorityDecisionRecorder` under ILK-002).

**Post-MVP / Kernel 1.0**: a generalized, first-class `Decision` record
type spanning routing, pause, and assignment decisions uniformly. Today,
route and work-claim state changes are their own append-only tables
(`request_routes`, `work_claims`), which already satisfy this document's
audit acceptance criteria for the vertical slice without needing a shared
abstraction — see [ILK-008](#ilk-008-audit).

Invariants:

- Kernel decisions MUST be limited to security, schema administration,
  connection admission, routing, delivery, subscription, work
  coordination, persistence mediation, and other hub responsibilities.
- A service-specific business decision SHOULD be represented as a
  service-owned artifact carried by a request rather than as a new kernel
  decision type.
- Every kernel decision MUST be a first-class durable record containing
  its type, outcome, responsible service or administrator, request ID,
  time, relevant security and schema revisions, and affected
  administrative objects. An authority decision produced by an external
  policy evaluator additionally records that evaluator's identity and the
  policy bundle/version it claimed to evaluate (ADR-0013). **MVP** for
  authority decisions; **Post-MVP** for a generalized type covering
  routing/work decisions too.
- Reversal or supersession MUST create another decision linked to the
  earlier record.

Acceptance criteria:

- A caller can reconstruct why a request was admitted, denied, routed,
  paused, delivered, or assigned using recorded inputs and policy
  versions. **MVP** for admit/deny; **Post-MVP** for a uniform routed/
  paused/delivered/assigned reconstruction API (today this evidence is
  reconstructable by joining `request_routes` and `work_claims`, not
  through one generalized decision query).
- Reversing an administrative or routing decision leaves the earlier
  decision available.
- Adding a service-specific business outcome does not require adding a
  kernel decision enum variant.

### ILK-008: Audit

**Scope: MVP** — the minimum audit evidence needed to reconstruct the
vertical slice already exists, spread across each capability's own
append-only table (replay audit, admission audit, authority decisions,
subscription history, route/claim status history). A single unified audit
log across all capabilities, including ones that are themselves Post-MVP
(artifact mediation, events), is Kernel 1.0.

Invariants:

- Security and governance actions MUST append an audit record in the same
  successful transaction as their governed state change.
- Audit records MUST NOT be updated or deleted through kernel contracts.
- Each record MUST include its event type, request ID where applicable,
  source service, instance and key, namespaced action, artifact and
  permission schema versions, administrative revision, time, outcome, and
  correlation ID (correlation ID is Post-MVP — see ILK-005). Route records
  additionally include destination service and subscription.
- Schema publication, activation, suspension, supersession, grant,
  revocation, connection, routing, replay, delivery, and work decisions
  MUST be auditable.

Acceptance criteria:

- A successful governed request or administrative change has a
  corresponding audit record.
- A rejected security-sensitive request or administrative action produces
  an audit record without a governed state change.
- Normal application credentials cannot update or delete audit history.

### ILK-009: Events

**Scope: Post-MVP / Kernel 1.0 — the entire capability.** Unimplemented;
the vertical slice does not publish or consume typed events. Full text
preserved in [Section 7](#7-future-kernel-kernel-10).

### ILK-010: Subscriptions

**Scope: Split.**

**MVP**: create/list/disable of inclusive subscriptions, matching against
subscriptions already active at submission time, and idempotent route
materialization (all Complete today).

**Post-MVP / Kernel 1.0**: exclusive consumer groups, `all_of` state
selectors, backlog matching, durable delivery cursors, route transition
history, and hardened production outbound handshake transport.

**External infrastructure**: capacity-aware delivery, worker/node
placement, and retry-timing policy belong to Taskmaster, not the kernel —
see [ADR-0011](decisions/0011-move-scheduling-policy-outside-the-kernel.md)
and [Section 8](#8-external-service-responsibilities).

- Implementation: `src/kernel/subscriptions.rs`
- Independent contract test: `tests/subscription_contract.rs`

Invariants:

- **MVP** — A service MUST be able to create, inspect, and disable its
  subscriptions through kernel contracts.
- **MVP** — A subscription MUST identify its stable service owner and one
  or more approved request, event, artifact, or work types.
- **MVP** — A request-receiving subscription MUST declare `exclusive` or
  `inclusive` delivery semantics; an omitted or unknown mode MUST fail
  closed.
- **Post-MVP / Kernel 1.0** — An exclusive subscription MUST declare an
  approved consumer-group identity. All services in that group compete for
  one request/group route and one completion; failover reassigns that
  route rather than resubmitting the request.
- **MVP** — An inclusive subscription MUST create an independent route for
  every matching stable destination service within the request's routing
  window.
- **Post-MVP / Kernel 1.0** — A subscription MAY require multiple typed
  state predicates. The minimum semantics MUST be `all_of`, evaluated from
  one consistent committed snapshot; every predicate must be true before a
  route becomes eligible. (Kept as a small deterministic declarative
  mechanism over trusted committed state — not a business rules engine.)
- **MVP** — Subscription modes, group identities, selectors, predicate
  sets, referenced schema versions, and routing-window policies MUST be
  immutable after creation. Replacement creates a new version and
  preserves the old definition.
- **MVP** — Selector predicates MUST be declarative approved fields and
  fixed operators; caller-supplied SQL, code, database identifiers, and
  executable expressions are forbidden.
- **Post-MVP / Kernel 1.0** — Committing a subscription MUST make
  pre-existing matching pending requests eligible for routing;
  subscription timing MUST NOT determine whether a request is retained.
  (This is backlog matching — MVP's vertical slice requires the
  subscription to already be active before the request is submitted.)
- **MVP** — The subscription registry supplies eligible destination
  services; it MUST NOT be overwritten with route progress or work
  history. **Post-MVP** — a durable wakeup cursor (today, matching is a
  simple active-set query, not a cursor-based scan).
- **Post-MVP / Kernel 1.0** — The kernel MUST use a durable subscription
  cursor or equivalent wakeup marker to find both new and pre-existing
  matching requests without loss.
- **MVP** — Subscription changes MUST be authorized and audited.
- **External infrastructure** — Pausing or deferring delivery for
  readiness, health, or capacity reasons is scheduler policy (ADR-0011)
  and MUST NOT delete or disable durable subscription state.
- **Post-MVP / Kernel 1.0** — Every kernel instance MUST continuously
  discover reachable instances for active subscriptions and complete a
  fresh, mutual proof-of-possession handshake before delivering to an
  instance. (The discovery/handshake mechanism exists; production-hardened
  outbound transport is the remaining piece.)

Acceptance criteria:

- A service receives or can retrieve only requests or events matching its
  active subscriptions, destination, approved schemas, and authorization
  scope. **MVP.**
- With no matching subscription, an accepted request remains durably
  pending. Creating an eligible matching subscription later exposes that
  backlog to the subscriber without requiring the source to retry or know
  the subscriber's runtime identity. **Post-MVP** (backlog matching).
- The kernel's eligibility query returns incomplete routes filtered by
  active subscription, authorization, and handshake state, excluding
  completed routes and routes protected by an active work claim. An
  external scheduler service selects which eligible route to claim next
  and for which worker; readiness and capacity are scheduler policy
  inputs, not kernel filters (see
  [ADR-0011](decisions/0011-move-scheduling-policy-outside-the-kernel.md)).
  **MVP — and the single largest remaining gap before `v0.1.0`**; see
  [Section 6](#6-current-implementation-status).
- If an exclusive destination instance or service fails, its assignment
  lease expires and the same route can be fenced and reassigned to
  another eligible service in the consumer group. No new request is
  created. **Post-MVP** (exclusive groups); the underlying fence/lease
  mechanism is MVP-complete for the inclusive case (ILK-011).
- A stale worker cannot renew, release, or complete a reassigned route
  because every mutation requires the current fencing token. **MVP**
  (proven for work claims today; "route revision" and "assignment ID" as
  separate concepts from the fencing token are Post-MVP — see ILK-011).
- Concurrent evaluation produces at most one exclusive request/group route
  or one inclusive request/destination route. Exactly one active
  assignment, one active claim, and one successful completion may exist
  per route. **MVP** for inclusive; **Post-MVP** for exclusive-group.
- The selector version and state revisions used for each eligibility
  decision remain queryable; later state mutations do not rewrite prior
  decisions. **Post-MVP** (coupled to `all_of` selectors).
- Disabling a subscription prevents new deliveries without deleting its
  history. **MVP.**
- A scheduler deferring claims for saturation, stale health, or lack of
  capacity does not advance or lose the durable cursor; resumed claiming
  picks up from the same eligible set (ADR-0011). **External
  infrastructure** — depends on the eligible-route query (MVP gap above).
- One unreachable subscriber does not prevent kernel startup or discovery
  of other subscribers; its delivery remains paused and is retried with
  backoff. **Post-MVP** (production handshake transport hardening).

Implementation status:

- Complete: typed subscription UUIDs and event types; stable-service
  ownership; durable create, history list, active list, and disable
  contracts; one-active subscription uniqueness; append-only
  create/disable audit; protected disabled history; PostgreSQL adapter;
  distinct eligible-instance discovery; per-kernel signed
  proof-of-possession reconciliation; append-only handshake persistence;
  failure isolation; fresh-handshake delivery gate; and isolated plus live
  persistence tests.
- Complete: signed REST operations for the subscription lifecycle —
  `POST /v1/subscriptions` (create), `GET /v1/subscriptions` (history, or
  active-only via `?active=true`), and `DELETE /v1/subscriptions/{id}`
  (disable) — dispatched from `src/http.rs` only after the existing
  signature/replay/admission gate admits the request. The caller's own
  verified identity (`VerifiedServiceRequest::service_id`), never a
  request-body field, is what the domain layer uses as the owning
  service, so a caller can only ever create, list, or disable its own
  subscriptions; disabling another service's subscription is
  indistinguishable from disabling one that does not exist.
- Complete: create and disable additionally require an ILK-002 authority
  decision (see ILK-002's own status above for the evaluator wiring); list
  does not, since it changes no governed administrative state.
- Complete (this is MVP): typed `DeliveryMode` on `Subscription` — only
  `Inclusive` exists so far, modeled as an enum from the start (not a
  bool) because ILK-010 requires an omitted or unknown mode to fail
  closed, not default to some behavior.
  `SubscriptionRepository::find_active_by_event_type` is the new
  kernel-internal (never directly HTTP-exposed) query request
  materialization uses to find every currently-active subscription
  matching a request's action, across all owning services.
- Complete (this is MVP): request-to-route materialization. Submitting a
  request (`POST /v1/requests`) matches its action against active
  inclusive subscriptions (`SubscriptionRouter` in `src/http.rs`,
  composing `SubscriptionService` and `RouteService` without either
  kernel module depending on the other's repository) and idempotently
  materializes a `Route` per match, keyed by `(request_id,
  subscription_id)` so repeated scans or retries never create a second
  route. A materialization failure does not fail the submission response
  — the request is already durably accepted (ILK-003 requires acceptance
  to not depend on subscription state) — it is logged and naturally
  retried if the client retries.
- Post-MVP / Kernel 1.0: exclusive delivery with consumer groups,
  immutable `all_of` state selectors, backlog matching (a subscription
  committed *after* a request currently never finds it — only
  subscriptions active at submission time are considered), route
  transition history, delivery cursors, and production outbound handshake
  transport.
- Remaining MVP gap: the eligible-route query contract external scheduler
  services will use does not exist yet (ADR-0011). See
  [Section 6](#6-current-implementation-status).
- External infrastructure: capacity-aware delivery, worker/node placement,
  and retry-timing policy. Those belong to an external scheduler service,
  not the kernel (ADR-0011) — see
  [Section 8](#8-external-service-responsibilities).

### ILK-011: Work claims

**Scope: Split.**

**MVP**: atomic claim/renew/release/complete with lease and fencing, and
one active claim per route (all Complete). The minimal eligible-route
query a scheduler needs to find something to claim is also MVP, but is not
yet built — see [Section 6](#6-current-implementation-status).

**Post-MVP / Kernel 1.0**: administrator-authorized forced claim
revocation (only expiry, release, and completion exist today — no
admin-forced revoke), and distinguishing "route revision" and "assignment
ID" from the fencing token as separate concepts (today deliberately
conflated: the fencing token alone identifies the current claim).

**External infrastructure**: which eligible route a worker should claim
next, and any priority/capacity/ordering policy, belongs to Taskmaster —
see [ADR-0011](decisions/0011-move-scheduling-policy-outside-the-kernel.md).

Invariants:

- **MVP** — At most one unexpired active claim may exist for the same
  work item.
- **MVP** — Every work item MUST originate from a durable request or an
  explicitly linked kernel coordination record; work MUST NOT create an
  unrelated business object model inside the kernel.
- **MVP** — Claim acquisition and renewal MUST be atomic.
- **MVP** — Claims MUST expire or be explicitly released so abandoned
  work can be recovered.
- **MVP** — Only the current claim holder may complete or release claimed
  work.
- **MVP** (fencing token) / **Post-MVP** (route revision, assignment ID as
  distinct fields) — A claim MUST be bound to the route revision,
  assignment ID, worker service and instance, lease, and monotonically
  increasing fencing token.
- **MVP** — Route reassignment MUST occur only after atomic release,
  expiry, or an authorized revocation transition. Liveness observations
  alone MUST NOT silently transfer ownership. (Authorized *administrative*
  revocation specifically is Post-MVP; expiry and release are MVP.)

Acceptance criteria:

- Concurrent claim attempts produce exactly one active holder. **MVP** —
  proven directly.
- Another worker can claim work after the prior claim expires. **MVP** —
  proven directly.
- A stale holder cannot complete work after losing its claim. **MVP** —
  proven directly.
- Concurrent failover and completion produce one winner: either the
  current holder completes, or reassignment advances the fence and makes
  that holder stale. **MVP** — proven directly.

Implementation status:

- Complete: `WorkClaim`, `WorkClaimRepository`, and `WorkClaimService`
  (`src/kernel/work_claims.rs`) — atomic `claim`/`renew`/`release`/
  `complete` bound to a route, the caller's own verified worker service
  and instance, a lease window, and a fencing token that increases by
  exactly one each time a route is claimed. `claim` fails as
  `RouteNotFound` if the route does not exist or is not assigned to the
  caller (indistinguishable to the caller, matching how disabling another
  service's subscription looks identical to disabling one that does not
  exist), and as `AlreadyClaimed` if a current, unexpired claim exists;
  otherwise it supersedes whatever claim previously existed.
  `renew`/`release`/`complete` fail as `Fenced` for a stale holder —
  including one that presents a fencing token that was current but has
  since been superseded — exactly like a stale holder losing a lease.
  PostgreSQL enforces the append-only, terminal-once status transition
  structurally (`protect_work_claim()` in migration 0017): a claim's
  identity fields are immutable, its lease may only be extended while
  still `active`, and once terminal (`completed`/`released`/`expired`)
  its status can never revert.
- Complete: governed HTTP routes — `POST /v1/routes/{route_id}/claims`,
  `POST /v1/claims/{id}/renew`, `POST /v1/claims/{id}/release`, and
  `POST /v1/claims/{id}/complete`. No separate ILK-002 authority decision
  gates these, matching `POST /v1/authority/schemas`'s precedent: a route
  already encodes "this destination is entitled to this work" through the
  subscription that produced it, so the repository-level ownership check
  is the only authorization these need.
- Concurrency proven directly: sixteen threads racing to claim the same
  route produce exactly one success and fifteen `AlreadyClaimed` results
  (`tests/work_claim_contract.rs`), independent of PostgreSQL.
- Remaining MVP gap: the eligible-route query a scheduler calls before it
  can propose a claim at all (see
  [Section 6](#6-current-implementation-status)) — `claim`/`renew`/
  `release`/`complete` are done, but nothing yet tells a caller *which*
  route IDs exist to claim.
- Post-MVP / Kernel 1.0: administrator-authorized forced claim revocation;
  route-revision/assignment-ID distinctness (currently conflated with the
  fencing token as a deliberate simplification).
- External infrastructure: any scheduling policy (which eligible route a
  worker should claim next, priority, capacity) — deliberately out of
  kernel scope (ADR-0011) — and wiring a reference worker
  (`infernal-taskmaster-simple`, still an unimplemented stub) to actually
  call these routes.

### ILK-012: Idempotency

**Scope: Split.**

**MVP**: request-level idempotency, which is exactly what ILK-003's
request-ID/fingerprint binding and safe-retry classification already
provide (there is no separate ILK-012 implementation — this capability is
realized entirely through ILK-003's mechanics).

**Post-MVP / Kernel 1.0**: idempotency for mediated artifact writes and
promised events, which cannot exist before their underlying capabilities
(ILK-006, ILK-009) do.

Invariants:

- **MVP** — Mutating requests MUST use their stable request ID as an
  idempotency key scoped to the authenticated source and semantic request
  fingerprint.
- **MVP** — Repeating the same request with the same key MUST return the
  original result and MUST NOT repeat its effects.
- **MVP** — Reusing a key with a materially different request MUST be
  rejected.
- **MVP** — Concurrent requests with the same key MUST converge on one
  committed result.

Acceptance criteria:

- Retrying after a lost response creates only one accepted request,
  mediated artifact write, administrative effect, audit change, and
  promised event. **MVP** for the accepted request and audit change;
  **Post-MVP** for the artifact write and promised event (ILK-006/009 do
  not exist yet).
- A key collision with a different payload returns a deterministic
  conflict. **MVP** — proven (`request_id_cannot_be_rebound_to_another_action_or_fingerprint`,
  `request_id_cannot_be_rebound_to_different_semantic_content`).

### ILK-013: Mediation

**Scope: MVP** — structural invariant, true by construction across every
kernel module (every repository trait uses fixed statements and typed
parameters; nothing accepts caller-supplied SQL). No further work is
required for `v0.1.0`; it is included here because it is a permanent
kernel property the vertical slice depends on, not because there is a
remaining task.

Invariants:

- Services MUST submit business communication and work through
  authenticated Request contracts. Administrative state MUST use
  separately authenticated, explicitly typed administration contracts.
- No caller, including an administrative service, may submit SQL or
  database command fragments for the kernel to execute.
- Worker credentials MUST NOT grant direct write access to kernel-owned
  tables, event storage, or audit history.
- Kernel persistence adapters MUST use kernel-owned statement structure
  and bound values; caller-controlled identifiers or SQL structure are
  prohibited.
- Database proxying MUST mean that the hub performs an approved fixed
  storage or retrieval operation for a request; it MUST NOT mean a
  generic database, query, table, procedure, or expression proxy.
- The kernel MUST enforce identity, replay, admission, schema approval,
  authority, validation, idempotency, versioning, audit, and event rules
  at the mediation boundary.

Acceptance criteria:

- A service can submit, route, receive, and coordinate supported work
  using only Request and administration contracts.
- A service's runtime credentials cannot directly insert, update, or
  delete kernel-owned records.
- SQL-shaped operations are rejected before a repository or database
  adapter is called.
- Bypassing one contract cannot bypass the cross-cutting kernel
  invariants.

## 4. MVP end-to-end acceptance test

Each requirement MUST have automated tests at the lowest practical layer:
unit tests for policy and state-transition rules, database integration
tests for immutability/uniqueness/concurrency/rollback, contract tests for
authentication/authorization/validation/idempotency, and end-to-end tests
for the full vertical slice. Steps 1–13 below are individually proven
today; step 14 (failure/recovery) is Section 5. What is *not* yet proven
is the whole chain in one continuous run against a live PostgreSQL
backend, since step 9 does not exist as a callable contract yet.

| Step | Mechanism | Proof today |
| --- | --- | --- |
| 1. Authenticated service submits a signed Request | `POST /v1/requests`, `ServiceRequestVerifier` | `tests/service_request_signature_contract.rs` |
| 2. Kernel authenticates the service | Fixed HTTP Message Signature profile, ILK-001 | `tests/identity_contract.rs`, `tests/service_request_signature_contract.rs` |
| 3. Communication admission/replay protection | Default-deny admission + atomic nonce/request-ID replay | `tests/admission_contract.rs`, `tests/replay_protection_contract.rs`, `tests/service_request_gate_contract.rs` |
| 4. Kernel builds trusted authority facts, calls the external evaluator | `PolicyFacts::for_request_acceptance` → `HttpPolicyEvaluator` → Inquisitor | `tests/authority_contract.rs`, `infernal-inquisitor-simple`'s own test suite |
| 5. Kernel records/enforces the authority decision | `AuthorityService::authorize` + `AuthorityDecisionRecorder` | `every_authorize_call_durably_records_exactly_one_decision`, `authorize_fails_rather_than_return_an_unrecorded_decision` |
| 6. Accepted Request is durably persisted in PostgreSQL | `PostgresRequestRepository` | `tests/postgres_request_repository.rs` (ignored, live-DB) |
| 7. A basic active inclusive subscription matches the Request | `SubscriptionRepository::find_active_by_event_type` | `tests/subscription_contract.rs::find_active_by_event_type_matches_across_services_and_excludes_disabled` |
| 8. Kernel materializes a durable route | `SubscriptionRouter` → `RouteService::materialize` | `tests/route_materialization_contract.rs`, `tests/postgres_route_repository.rs` (ignored, live-DB) |
| 9. External scheduler queries eligible work | **Not implemented** | — this is the punch-list gap; see Section 6 |
| 10. Scheduler proposes a worker/route claim | `POST /v1/routes/{route_id}/claims` | `tests/work_claim_contract.rs`, colocated `work_claim_routes` HTTP tests in `src/http.rs` |
| 11. Kernel atomically arbitrates the claim (lease/fencing) | `WorkClaimService::claim` | `tests/work_claim_contract.rs`, `tests/postgres_work_claim_repository.rs` (ignored, live-DB) |
| 12. Worker completes the work through the kernel | `POST /v1/claims/{id}/complete` | `tests/work_claim_contract.rs::completion_is_terminal_and_cannot_be_renewed_or_released_afterward` |
| 13. Resulting state and audit evidence are durable | `protect_work_claim()` trigger + append-only tables | `tests/postgres_work_claim_repository.rs`'s `assert_database_guards` |
| 14. Restart/retry/failure cannot silently duplicate, lose, or incorrectly complete work | see Section 5 | see Section 5 |

## 5. MVP failure/recovery tests

| Required proof | Test(s) | Status |
| --- | --- | --- |
| Retrying the same semantic Request does not create duplicate work | `acceptance_is_durable_through_the_repository_contract_and_safe_to_retry`, `concurrent_acceptance_has_one_fresh_result_and_no_duplicate_record`, `same_request_with_a_new_signature_is_a_safe_idempotency_retry` | Done |
| Reusing a Request ID for different content is rejected | `request_id_cannot_be_rebound_to_another_action_or_fingerprint`, `request_id_cannot_be_rebound_to_different_semantic_content` | Done |
| An unauthorized Request fails closed | `default_deny_when_no_grant_matches` | Done |
| An unavailable or malformed policy evaluator fails closed | `unreachable_evaluator_is_denied_never_implicitly_allowed` | Done |
| Two workers racing for the same route produce one valid owner | `concurrent_claim_attempts_on_the_same_route_produce_exactly_one_active_holder` | Done |
| After a claim expires, another worker can acquire the work | `another_worker_can_claim_after_the_prior_lease_expires` | Done |
| A stale worker cannot complete work after fencing/reassignment | `a_stale_holder_cannot_renew_release_or_complete_after_losing_its_claim` | Done |
| Restarting the kernel does not lose accepted Requests, routes, claims, authority decisions, or required audit state | `tests/postgres_request_repository.rs`, `tests/postgres_route_repository.rs`, `tests/postgres_work_claim_repository.rs`, `tests/postgres_authority_repository.rs` (all ignored, live-DB) | Proven per-capability; **not yet proven as one continuous restart test spanning the whole vertical slice** — punch-list item, Section 6 |

## 6. Current implementation status

Everything tagged **MVP — Complete** in Section 3 requires no further work
for `v0.1.0`: ILK-001 (Identity), ILK-002's request-acceptance authority,
ILK-003's immutable requests and inclusive route materialization, ILK-004,
ILK-007's authority-decision evidence, ILK-008's per-capability audit,
ILK-010's inclusive subscriptions, and ILK-011's claim/renew/release/
complete with fencing.

What remains before tagging `v0.1.0`:

1. **Finish the minimal eligible-route query needed by Taskmaster**
   (ILK-010/ILK-011 gap, vertical-slice step 9) — a read-only, authenticated
   query returning incomplete routes with no current active claim,
   filtered to routes the calling worker class is entitled to see. This is
   the single largest remaining gap; nothing downstream of it (claim,
   complete) is blocked on new kernel code.
2. **Wire a simple external Taskmaster against it** —
   `infernal-taskmaster-simple` is currently an eight-line stub; it needs
   enough logic to call the query above and propose a claim.
3. **Wire a simple worker through claim → execution → completion** — using
   the existing `POST /v1/routes/{route_id}/claims` and
   `POST /v1/claims/{id}/complete` routes, which are already MVP-complete.
4. **Close any missing audit/idempotency transaction requirements required
   by that path** — expected to be zero new invariants, since the
   individual pieces (acceptance, materialization, claim, completion) are
   each already transactional; this step is about confirming that,
   end-to-end.
5. **Run the failure/recovery acceptance tests** (Section 5) as one
   continuous scenario, including the restart proof that today only
   exists per-capability.

Nothing else is required to tag `v0.1.0`. In particular: exclusive
consumer groups, `all_of` selectors, backlog matching, route transition
history, correlation/causation, artifact content mediation, typed events,
and any scheduling policy are all explicitly out of scope for `v0.1.0` —
see Section 7.

## 7. Future Kernel / Kernel 1.0

These remain legitimate, permanent kernel responsibilities — they protect
authority, correctness, durability, or replay semantics — but none of them
block `v0.1.0`. Items already covered inline under their `ILK-*` section in
Section 3 are cross-referenced rather than repeated; capabilities that are
deferred in their entirety are given in full here.

Cross-referenced (see Section 3 for full invariants/acceptance criteria):

- **ILK-002** — destination-scoped route re-authorization (the
  `PolicyFacts::for_route` domain primitive already exists; only its live
  wiring is deferred); administrator-facing schema-activation workflow.
- **ILK-003** — exclusive-group routes and consumer-group semantics;
  append-only route transition history; backlog matching (a subscription
  created after a request does not yet retroactively see it).
- **ILK-007** — a generalized `Decision` record type spanning routing,
  pause, and assignment decisions uniformly, rather than relying on each
  capability's own append-only table.
- **ILK-008** — a unified audit log spanning capabilities that do not yet
  exist (artifact mediation, events).
- **ILK-010** — exclusive consumer groups with fenced reassignment across
  a group; generalized `all_of` state selectors (kept intentionally small
  and declarative — a deterministic eligibility mechanism over trusted
  committed state, not a business rules engine); durable subscription
  cursors and replay semantics beyond the current active-set match; route
  transition history; hardened production outbound handshake transport.
- **ILK-011** — administrator-authorized forced claim revocation; treating
  route revision and assignment ID as distinct from the fencing token.
- **ILK-012** — idempotency for mediated artifact writes and promised
  events, blocked on ILK-006 and ILK-009 existing first.
- **Multi-replica kernel correctness** — `GET /v1/kernel-identity` behind
  multiple replicas remains an open follow-up (ADR-0014). Per the
  boundary rule, load-balancing/discovery across replicas is
  infrastructure, but identity, fencing, and proof-of-possession
  correctness across replicas remain kernel responsibilities.

Deferred in full (not required by, and not described piecemeal in, the
MVP vertical slice):

### ILK-005: Relationships

Invariants:

- The kernel MUST define only universal request relationships such as
  correlation, causation, retry, response, routing, delivery, and work
  origin.
- Service-specific artifact relationship types MUST be namespaced and
  declared by an approved schema owned by the relevant service.
- Every stored link MUST identify its declared type, schema version,
  stable source, and stable target.
- The kernel MUST validate structural relationship metadata without
  assuming the business meaning of service-owned artifact links.
- Relationship history MUST be append-only or explicitly versioned.

Acceptance criteria:

- Requests can be queried by correlation, causation, response, delivery,
  and work-origin relationships.
- The kernel rejects an unknown, inactive, unnamespaced, or structurally
  invalid service-defined relationship type.
- Adding a new approved service relationship type requires no kernel code
  change.

Implementation status: not started. Business/domain relationships (as
opposed to the universal ones above) are
[domain-owned](#9-explicitly-domain-owned-responsibilities), never kernel.

### ILK-006: Artifacts

Invariants:

- Each artifact type and permission vocabulary MUST be owned by a stable
  service namespace and reference an approved, versioned schema.
- The kernel MUST treat artifact business content as opaque and MUST
  inspect only the bounded metadata required for security, schema
  selection, routing, storage mediation, and integrity verification.
- An accepted artifact's content digest, schema reference, owner,
  submitting service, request provenance, and storage reference MUST be
  immutable.
- An artifact correction MUST create a new artifact or request and use an
  approved relationship to the artifact it replaces or supplements.
- Artifact storage and retrieval MUST occur through typed kernel requests
  and fixed persistence adapters; services MUST NOT choose tables,
  columns, predicates, functions, or SQL.

Acceptance criteria:

- An artifact can be retrieved or proxied and verified against the exact
  digest and schema version originally accepted.
- An attempt to overwrite artifact content or change its schema reference
  is rejected.
- Two services can introduce unrelated artifact schemas without adding
  Rust business-domain types to the kernel.
- A schema owner cannot activate its own schema or grant itself access
  unless a separately authorized administrator explicitly does so.

Implementation status: not started (schema *registration*, the part this
capability shares with ILK-002, is already Complete there — see ILK-002).
Pending: immutable artifact descriptors and fixed artifact
storage/retrieval mediation. The kernel owns this governed
mediation/integrity/provenance contract; physical byte storage MAY be
implemented by an external storage adapter/service rather than becoming a
kernel-hosted object store — see
[Section 8](#8-external-service-responsibilities).

### ILK-009: Events

Invariants:

- An event MUST describe an already committed fact and MUST NOT announce
  a state change that can later roll back.
- Every event MUST have a stable event ID, declared type and schema
  version, occurrence time, and correlation ID.
- Kernel event types MUST describe hub facts such as request acceptance,
  authorization, routing, delivery, work, connection, and administration.
- Service-domain events MUST be namespaced and defined by an approved
  service schema rather than a hardcoded kernel business event enum.
- When a request promises an event, durable state and the event MUST be
  committed atomically.

Acceptance criteria:

- A failed or rolled-back request publishes no committed-change event.
- Consumers can distinguish event types and schema versions without
  inspecting an untyped payload.
- A newly approved service event schema can be routed without a kernel
  code change.

Implementation status: not started.

## 8. External service responsibilities

**Taskmaster (external scheduler).** Owns ordering, priority, worker/node
selection, CPU/GPU/resource-class placement, capacity, affinity,
backpressure, retry timing, Kubernetes placement, and infrastructure
health/capacity interpretation. See
[ADR-0011](decisions/0011-move-scheduling-policy-outside-the-kernel.md).
The kernel exposes only the trusted state and atomic operations necessary
for Taskmaster to make proposals (the eligible-route query, and the
claim/renew/release/complete contract) and remains the final arbiter of
eligibility and ownership. `infernal-taskmaster-simple` is the reference
implementation and is currently an unimplemented stub; wiring a minimal
version of it against the eligible-route query is on the `v0.1.0` punch
list (Section 6), but the scheduling *logic* itself is never kernel scope.

**Inquisitor (external policy evaluator).** Owns the allow/deny policy
algorithm only. It MUST remain stateless with respect to authoritative
authorization data; the kernel continues to own identities, grants, schema
references/status required for authority, trusted fact construction,
decision recording, and final enforcement. Evaluator unavailable/error/
malformed response MUST remain fail-closed. See
[ADR-0013](decisions/0013-external-stateless-policy-evaluator-for-authority.md).
`infernal-inquisitor-simple` is the reference implementation and is
already Complete and integrated — no `v0.1.0` work remains here.

**External artifact/blob storage.** Physical artifact/blob storage MAY be
implemented by an external storage adapter/service. The kernel should own
the governed contract, provenance, and integrity requirements, and the
mediation boundary, rather than becoming a general-purpose object store
itself (ILK-006, Kernel 1.0 — not required for `v0.1.0`).

## 9. Explicitly domain-owned responsibilities

Business semantics MUST remain outside the kernel. This includes, without
limitation:

- engineering/CAD semantics;
- requirements semantics;
- document semantics;
- business workflow rules;
- domain-specific artifact relationships;
- domain-specific derived state;
- domain-specific decisions;
- AI reasoning; and
- business interpretation of artifacts.

The kernel MAY validate approved schemas and bounded metadata but MUST NOT
grow a universal business-object model. This is the same rule stated in
the kernel object boundary (Section 2): the only general
non-administrative object the kernel defines is a **Request**. Connected
services own the schemas, action vocabulary, artifacts, and
permission-policy vocabulary for their business domains.

## 10. Open design decisions

No contradiction with an accepted ADR was found while producing this
scope reclassification; every reclassification here is a scope label, not
a technical change. ADR-0009, ADR-0011, and ADR-0013 in particular already
anticipated this MVP/Kernel-1.0 split (explicit delivery modes, scheduling
policy moved outside the kernel, and a stateless external evaluator,
respectively) and remain fully consistent with it.

The requirements intentionally do not choose these implementation
details. The first is now the most urgent, since it gates `v0.1.0`:

- the eligible-route query contract's shape, worker-class declaration,
  pagination, and freshness semantics for external scheduler services
  (ADR-0011) — **blocks `v0.1.0`**;
- service-owned artifact-schema and permission-policy-schema formats;
- constrained policy evaluation language and scope matching rules;
- schema publication, administrator approval, and revocation workflow;
- universal request relationship representation and service-owned
  relationship schema format;
- artifact storage location and integrity mechanism;
- event transport and delivery guarantee;
- subscription cursor and replay semantics;
- claim lease duration and renewal protocol;
- idempotency retention period; and
- request payload/reference thresholds and storage-proxy limits.

Each consequential choice should be recorded as an ADR and linked back to
the affected `ILK-*` requirements.
