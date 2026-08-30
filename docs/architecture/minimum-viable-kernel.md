# Minimum viable kernel

> Status: Requirements draft  
> Last reviewed: 2026-08-30
> Owners: TODO

This document has two jobs. First, it defines the **Minimum Viable Infernal
Law Kernel (`v0.1.0`)**: one complete, provable, governed-work vertical
slice, narrow enough to actually finish. Second, it preserves every other
requirement the kernel is expected to own eventually, explicitly classified
so that scope never expands by accident and nothing is silently deleted
because it isn't needed yet.

Every requirement below is classified into exactly one of:

- **MVP Kernel** — required to tag `v0.1.0`.
- **Future Kernel / Kernel 1.0** — a real, permanent kernel responsibility
  (it protects authority, communication, or correctness) that MUST NOT
  block `v0.1.0`.
- **External Infrastructure Service** — optimization, placement, or
  policy-algorithm responsibility that belongs to a service other than the
  kernel (Taskmaster, Inquisitor, or a storage adapter).
- **Domain-Owned Service Responsibility** — data, search, business
  semantics, or domain mutation that belongs to the services built on top
  of the kernel, never to the kernel itself.

The keywords **MUST**, **MUST NOT**, **SHOULD**, and **MAY** express
requirement strength throughout. This is a **scope-reduction-by-classification**
document, not a simplification-by-deletion one: a requirement that is real
and useful but not required for `v0.1.0` is reclassified and preserved, never
dropped.

## Table of contents

1. [Objective](#1-objective)
2. [Architectural boundary](#2-architectural-boundary)
3. [MVP definition](#3-mvp-definition)
4. [MVP vertical slice](#4-mvp-vertical-slice)
5. [MVP capabilities](#5-mvp-capabilities)
6. [MVP failure/recovery acceptance tests](#6-mvp-failurerecovery-acceptance-tests)
7. [Current MVP implementation status](#7-current-mvp-implementation-status)
8. [Future Kernel / Kernel 1.0](#8-future-kernel-kernel-10)
9. [External infrastructure services](#9-external-infrastructure-services)
10. [Domain-owned services](#10-domain-owned-services)
11. [Namespace, data, and search ownership](#11-namespace-data-and-search-ownership)
12. [Open design decisions](#12-open-design-decisions)

## 1. Objective

Infernal Law is a **zero-trust mediation kernel**. Its job is to own:

- authenticated service identity;
- communication admission and replay protection;
- authority enforcement;
- durable Request state;
- routing correctness;
- route ownership;
- claims, leases, and fencing;
- idempotency;
- audit and consequential decision evidence;
- the trusted communication path between services.

The kernel MUST NOT become the authoritative business datastore, search
engine, workflow engine, scheduler, geometry engine, rules engine, or
universal artifact database. Those are jobs for other services, built on
top of the trust the kernel provides.

The organizing rule for this entire document:

> **The kernel owns authority, communication, and correctness.**
>
> **External infrastructure services own optimization and execution
> policy.**
>
> **Domain services own data, search, business semantics, and domain
> mutation.**

Concretely, each party answers a different question:

- **The kernel** answers: *is this operation authenticated, authorized,
  valid, durable, eligible, unique, replay-safe, and safely ownable?*
- **Taskmaster** (external scheduler) answers: *of the work the kernel says
  may run, what should run next and where?*
- **Inquisitor** (external policy evaluator) answers: *given this
  kernel-supplied fact bundle and policy version, does policy evaluate to
  allow or deny?*
- **Domain services** answer: *what does this artifact/request mean, what
  business action should be performed, and how should the resulting data
  be stored, indexed, or searched?*

Do not move a responsibility out of the kernel merely to reduce its size if
doing so would create a second authority source or let an external service
violate a kernel invariant. Likewise, do not keep a responsibility in the
kernel merely because the kernel happens to consume information that
responsibility produces.

## 2. Architectural boundary

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
  that reads the kernel's eligible-route query and may recommend which
  eligible work should run next and, optionally, where. It owns
  optimization policy (ordering, priority, affinity, resource-class
  placement, capacity, backpressure timing, retry timing); it holds no
  elevated database access and cannot bypass claim arbitration —
  recommending is not assigning: an eligible worker submits the actual
  claim under its own authenticated identity, and the kernel alone
  atomically arbitrates whether that claim succeeds. The kernel is its
  only source of registered request, route, health/capacity-relay, and
  claim state — a scheduler never receives that state from a worker
  directly or from any other event source. See
  [ADR-0011](decisions/0011-move-scheduling-policy-outside-the-kernel.md)
  and [Section 9](#9-external-infrastructure-services).
- **Policy evaluator** (Inquisitor) — an ordinary, non-privileged service
  principal that holds no authorization data of its own. The kernel sends
  it a fact bundle (source, action, schema versions, scope/artifact
  identifiers, grants, and destination when applicable) and it returns an
  allow/deny verdict plus the policy bundle/version it evaluated. The
  kernel alone owns the grants, schemas, and audit trail; an unreachable or
  erroring evaluator is denial, never implicit allow. See
  [ADR-0013](decisions/0013-external-stateless-policy-evaluator-for-authority.md)
  and [Section 9](#9-external-infrastructure-services).
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
  **Future Kernel** — see [ILK-010](#ilk-010-subscriptions).
- **Inclusive subscription** — a fan-out subscription for which every
  matching stable destination service owns an independent request route
  and completion. **MVP Kernel.**
- **Action name** — a service-owned, namespaced action declared by an
  approved artifact and permission-policy schema; it is not a kernel-wide
  enum.
- **Artifact** — service-owned content carried by reference or value in a
  request. The kernel treats its business content as opaque except for
  approved schema metadata, routing fields, content length, and content
  digest. **MVP carries only the schema version reference required for
  authority (ILK-002); actual artifact content mediation is Future Kernel —
  see [ILK-006](#ilk-006-artifacts) and
  [Section 11](#11-namespace-data-and-search-ownership).**
- **Artifact schema** — a namespaced, versioned contract defined by the
  service that owns an artifact type. **MVP Kernel** (publication already
  implemented under ILK-002).
- **Permission-policy schema** — a namespaced, versioned declaration from a
  service describing the actions and permission fields meaningful for its
  artifacts. Administrators, not the defining service, control activation
  and grants under that schema. **MVP Kernel.**
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

- a stable request ID — **MVP Kernel**;
- authenticated source service, instance, and key IDs — **MVP Kernel**;
- a namespaced action — **MVP Kernel**;
- artifact type, schema name, schema version, and schema owner — **MVP
  Kernel** (schema *reference* only; see ILK-006 for content mediation);
- permission-policy schema name, version, and owner — **MVP Kernel**;
- artifact ID or payload reference plus content digest — **Future Kernel**,
  not carried by the request today (see [ILK-006](#ilk-006-artifacts));
- correlation and optional causation IDs — **Future Kernel**, not carried
  by the request today (see [ILK-005](#ilk-005-relationships)); and
- creation, expiry, replay, and idempotency metadata — **MVP Kernel**
  (creation, replay, and idempotency; explicit request expiry is Future
  Kernel).

A service MAY publish new artifact and permission-policy schemas in its own
namespace. Publication MUST NOT activate a schema, authorize the publisher,
or create a grant. A security administrator MUST explicitly approve schema
versions and bind identities to permissions. The kernel MUST make and
retain the final allow-or-deny result. **MVP Kernel** — implemented in
full.

### Authoritative state boundary

**MVP Kernel** — this entire boundary is load-bearing for the vertical
slice and is already true by construction:

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

This is a statement about **kernel-owned** state only. It says nothing
about where a domain service stores *its own* authoritative data — see
[Section 11](#11-namespace-data-and-search-ownership).

### Routing ledger

The kernel separates immutable intent, interest, destination progress, and
exclusive ownership:

| Record | Identity and purpose | Multiplicity | Scope |
| --- | --- | --- | --- |
| Request | Source-authenticated intent and matching metadata | One accepted record per source/request ID | MVP Kernel |
| Subscription | A stable service's declared interest and wakeup cursor | Zero or more matches per request | MVP Kernel (inclusive only; cursor is a simple active-set match, not a durable replay cursor — see ILK-010) |
| Request route | Deduplication and completion boundary for an exclusive group or inclusive destination | At most one per request/group or request/destination | MVP Kernel (inclusive only) |
| Route transition | Append-only evidence of ready, claimed, completed, paused, or terminal progress, including the applicable subscription | Many per route | Future Kernel as a dedicated ledger — MVP gets equivalent minimum evidence from the route and work-claim tables' own append-only status history, which already satisfies the vertical slice's audit acceptance criteria (see [ILK-008](#ilk-008-audit)) |
| Work claim | Exclusive lease naming the worker currently handling a route | At most one active claim per route; history retained | MVP Kernel |

An accepted request with no matching subscription is **unrouted**, not
failed. When a subscription matches, the kernel idempotently creates or
wakes the request route for that stable destination. The kernel's
eligible-route query uses active subscription state to expose which
incomplete routes are eligible; it does not select which one runs next or
on which worker — recommending eligible work, and optionally where it
should run, is scheduler policy, external to the kernel (see
[ADR-0011](decisions/0011-move-scheduling-policy-outside-the-kernel.md)).
The work-claim contract then atomically arbitrates whichever claim an
eligible worker submits under its own authenticated identity: authorized,
still eligible, unclaimed, and fencing-current, or rejected. A completion
is scoped to that route and records the subscription and worker
responsible. It does not complete the parent request for any other
destination.

### Transaction boundary

**MVP Kernel** — for every governed MVP mutation, all kernel-owned durable
state required for that mutation MUST commit atomically before the kernel
reports success or releases an externally visible governed effect. The
kernel MUST NOT report success for a governed mutation if only part of
its required kernel-owned state became durable.

Depending on the operation, that state may include:

- request acceptance and semantic fingerprint;
- authority decision evidence;
- subscription state;
- route materialization;
- work-claim, lease, and fencing state;
- completion state;
- replay and idempotency state;
- required audit evidence.

The kernel reports success only after the required kernel-owned
transaction commits.

This rule applies only to kernel-owned state. It does NOT imply that
domain artifact content, domain databases, search indexes, or other
service-owned persistence participate in the same PostgreSQL transaction
— see [Section 11](#11-namespace-data-and-search-ownership) for that
ownership boundary. Future capabilities such as artifact-content
mediation and typed events MUST define their own durability and
atomicity requirements when those capabilities are introduced, rather
than inheriting this one by default.

## 3. MVP definition

The **Minimum Viable Infernal Law Kernel** is the smallest kernel that can:

1. prove the complete governed-work vertical slice in
   [Section 4](#4-mvp-vertical-slice), end to end, against a real
   PostgreSQL backend; and
2. pass every required failure/recovery proof in
   [Section 6](#6-mvp-failurerecovery-acceptance-tests).

A capability that is real, useful, and even partially built is **not**
automatically MVP. It is MVP if and only if the vertical slice cannot be
proven without it. Everything else is preserved — never deleted — and
classified into Sections 8 through 11 by who should own it long-term:
Future Kernel, an external infrastructure service, or a domain service.

This is a deliberately narrow test. It excludes, for example, exclusive
delivery, generalized eligibility selectors, artifact content storage, and
any scheduling policy — all real, all eventually kernel-or-service
responsibilities, none required to prove the vertical slice works.

## 4. MVP vertical slice

The Minimum Viable Kernel exists once the kernel can prove this end-to-end
path:

1. An authenticated service submits a signed Request.
2. The kernel verifies identity, signature, freshness, replay state, and
   communication admission.
3. The kernel constructs trusted authority facts.
4. The kernel calls the external stateless policy evaluator.
5. The evaluator returns allow/deny and the policy version evaluated.
6. The kernel records the authority decision and remains the final
   enforcement point.
7. The Request is durably persisted in PostgreSQL.
8. A basic active inclusive subscription matches it.
9. The kernel creates one durable route.
10. Taskmaster queries the kernel for eligible routes.
11. Taskmaster may recommend which eligible work should run next.
12. An eligible worker submits a claim using its own authenticated
    identity, and the kernel atomically arbitrates ownership through
    claims, leases, and fencing.
13. The worker receives the governed work through the kernel.
14. The worker returns completion/result state through the kernel.
15. Required request, authority, route, claim, completion, and audit
    evidence remains durable across restart.

That vertical slice is the MVP. [Section 6](#6-mvp-failurerecovery-acceptance-tests)
lists the specific failure/recovery proofs `v0.1.0` also requires.
[Section 7](#7-current-mvp-implementation-status) is the short, current
answer to "what exactly is left before tagging `v0.1.0`."

Each step maps onto a concrete kernel mechanism and the test that proves
it:

| Step | Mechanism | Proof today |
| --- | --- | --- |
| 1. Authenticated service submits a signed Request | `POST /v1/requests`, `ServiceRequestVerifier` | `tests/service_request_signature_contract.rs` |
| 2. Kernel verifies identity, signature, freshness, replay, admission | Fixed HTTP Message Signature profile (ILK-001) + default-deny admission + atomic nonce/request-ID replay | `tests/identity_contract.rs`, `tests/service_request_signature_contract.rs`, `tests/admission_contract.rs`, `tests/replay_protection_contract.rs`, `tests/service_request_gate_contract.rs` |
| 3. Kernel constructs trusted authority facts | `PolicyFacts::for_request_acceptance` | `tests/authority_contract.rs` |
| 4. Kernel calls the external stateless policy evaluator | `HttpPolicyEvaluator` → Inquisitor | `tests/authority_contract.rs`, `infernal-inquisitor-simple`'s own test suite |
| 5. Evaluator returns allow/deny and the policy version evaluated | `HttpPolicyEvaluator` response parsing | Colocated tests in `src/infrastructure/http_policy_evaluator.rs` |
| 6. Kernel records the authority decision and remains final enforcement | `AuthorityService::authorize` + `AuthorityDecisionRecorder` | `every_authorize_call_durably_records_exactly_one_decision`, `authorize_fails_rather_than_return_an_unrecorded_decision` |
| 7. Request is durably persisted in PostgreSQL | `PostgresRequestRepository` | `tests/postgres_request_repository.rs` (ignored, live-DB) |
| 8. A basic active inclusive subscription matches it | `SubscriptionRepository::find_active_by_event_type` | `tests/subscription_contract.rs::find_active_by_event_type_matches_across_services_and_excludes_disabled` |
| 9. Kernel creates one durable route | `SubscriptionRouter` → `RouteService::materialize` | `tests/route_materialization_contract.rs`, `tests/postgres_route_repository.rs` (ignored, live-DB) |
| 10. Taskmaster queries the kernel for eligible routes | `GET /v1/routes/eligible` → `EligibleRouteQuery` | `tests/route_materialization_contract.rs`, `tests/work_claim_contract.rs`, colocated `eligible_route_routes` tests in `src/http.rs`, `tests/postgres_route_repository.rs`/`tests/postgres_work_claim_repository.rs` (ignored, live-DB) |
| 11. Taskmaster may recommend which eligible work should run next | Taskmaster's own scheduling policy — external to the kernel, no kernel API call ([ADR-0011](decisions/0011-move-scheduling-policy-outside-the-kernel.md)) | `infernal-taskmaster-simple`'s own test suite (FIFO scheduling policy) |
| 12. An eligible worker submits a claim under its own authenticated identity, and the kernel atomically arbitrates ownership (claims/leases/fencing) | `POST /v1/routes/{route_id}/claims` → `WorkClaimService::claim` | `tests/work_claim_contract.rs`, colocated `work_claim_routes` HTTP tests in `src/http.rs`, `tests/postgres_work_claim_repository.rs` (ignored, live-DB) |
| 13. Worker receives the governed work through the kernel | `GET /v1/routes/{route_id}/request` → `RoutedRequestQuery` | `tests/route_materialization_contract.rs::find_returns_a_single_route_by_id_or_none_for_an_unknown_id`, colocated `routed_request_routes` tests in `src/http.rs`, `tests/postgres_route_repository.rs` (ignored, live-DB) |
| 14. Worker returns completion/result state through the kernel | `POST /v1/claims/{id}/complete` | `tests/work_claim_contract.rs::completion_is_terminal_and_cannot_be_renewed_or_released_afterward` |
| 15. Required evidence remains durable across restart | `protect_work_claim()` trigger + append-only tables | `tests/postgres_work_claim_repository.rs`'s `assert_database_guards`; see [Section 6](#6-mvp-failurerecovery-acceptance-tests) for the full-restart proof |

**Step 13 was a real gap, now closed.** A claimed route's
`WorkClaimResponse` still carries only `claim_id`, `route_id`,
`worker_service_id`, `worker_instance_id`, `fencing_token`, `status`,
`claimed_at`, and `lease_expires_at` — never the original Request's
action, scope, or schema — and `GET /v1/requests/{id}` is still
intentionally scoped to the request's *source* service only
(`RequestRepository::find(source_service, request_id)`). What closes the
gap is a new, separate read: `GET /v1/routes/{route_id}/request`
(`RoutedRequestQuery`, composing `RouteService::find` with
`RequestService::find`) resolves a route to the request behind it, but
only for the route's own destination service — the worker that claimed
it, or could claim it. A route belonging to another service, or that does
not exist, is indistinguishable to the caller, matching every other
ownership-hiding convention in this document. See ILK-003's own status
below and [Section 7](#7-current-mvp-implementation-status).

## 5. MVP capabilities

Every `ILK-*` identifier from the original requirements draft is preserved.
Each capability below is tagged **MVP Kernel**, **Split** (part of it gates
`v0.1.0`, part is Kernel 1.0), or **Future Kernel** (the whole capability
is deferred — its full text lives in
[Section 8](#8-future-kernel-kernel-10), not repeated here).

| ID | Capability | Scope for v0.1.0 |
| --- | --- | --- |
| ILK-001 | Identity | **Split** — stable/instance identity, per-instance signing, authenticated signed requests, freshness/replay protection, and attribution are MVP (all done); continuous discovery, hardened proof-of-possession renewal, multi-replica correctness, richer key rotation, and hardened reconciliation/recovery are Kernel 1.0 |
| ILK-002 | Authority | **Split** — request-acceptance authority is MVP; per-route re-authorization and schema-lifecycle administration UI are Kernel 1.0 |
| ILK-003 | Requests | **Split** — immutable durable requests, inclusive-only route materialization, and a destination-scoped read of request content are MVP (all done); correlation, exclusive groups, route history, and backlog matching are Kernel 1.0 |
| ILK-004 | Versions | **MVP Kernel** (the append-only/immutability invariant itself; administrative lifecycle workflow is external — see ILK-002) |
| ILK-005 | Relationships | **Future Kernel** — unimplemented, not required by the vertical slice |
| ILK-006 | Artifacts | **Future Kernel** + domain-owned by default — unimplemented, not required by the vertical slice; see [Section 11](#11-namespace-data-and-search-ownership) |
| ILK-007 | Decisions | **Split** — the authority decision record is MVP; a generalized Decision type spanning routing/pause/assignment is Kernel 1.0 |
| ILK-008 | Audit | **MVP Kernel** (minimum evidence to reconstruct the vertical slice already exists per-capability; a unified audit log is Kernel 1.0) |
| ILK-009 | Events | **Future Kernel** — unimplemented, not required by the vertical slice |
| ILK-010 | Subscriptions | **Split** — inclusive create/list/disable/materialize is MVP; exclusive groups, `all_of` selectors, backlog matching, cursors, route history are Kernel 1.0 |
| ILK-011 | Work claims | **Split** — claim/renew/release/complete with fencing is MVP (done); the eligible-route query is MVP (done); administrative forced revocation is Kernel 1.0 |
| ILK-012 | Idempotency | **Split** — request-level idempotency (via ILK-003) is MVP; idempotency for artifact writes/events is Kernel 1.0, blocked on ILK-006/009 |
| ILK-013 | Mediation | **MVP Kernel** — structural invariant, already true by construction |

### ILK-001: Identity

**Scope: Split.**

The MVP requires enough identity machinery to prove that every participant
in the governed-work vertical slice acts under its own authenticated
authority.

**MVP**: stable service identity, unique per-instance identity and signing
credentials, authenticated signed kernel requests, freshness/replay
protection, and attribution of accepted Requests and completed work to
the responsible service, instance, and key (all Complete today).

**Kernel 1.0**: continuous service-instance discovery, production-hardened
proof-of-possession renewal, multi-replica kernel identity correctness,
richer key rotation/lifecycle administration, and hardened instance
reconciliation/recovery behavior. These remain kernel security
responsibilities, but they do not gate the first governed-work vertical
slice unless explicitly exercised by the MVP acceptance tests.

- Implementation: `src/kernel/identity.rs`
- Independent contract test: `tests/identity_contract.rs`

Invariants:

- **MVP** — Every non-public request or administrative action MUST be
  attributable to exactly one authenticated service or administrator and
  verified credential.
- **MVP** — Every running service instance MUST have a unique instance ID
  and freshly generated keypair; no private key may be shared with
  another instance or persisted outside its signing process.
- **MVP** — Identity IDs MUST remain stable even if display names or
  credentials change.
- **MVP** — Worker identities MUST be represented as a service role or
  profile.
- **MVP** — The kernel MUST NOT accept user credentials as kernel
  credentials.
- **MVP** — Every signed kernel request MUST be authenticated and MUST be
  rejected as stale or replayed outside a bounded freshness window (see
  ILK-003's replay-protection acceptance criteria for the mechanism).
- **MVP** — Every accepted Request and completed unit of work MUST be
  attributable to the specific service, instance, and key responsible.
- **Kernel 1.0** — Service-instance discovery MUST run continuously, not
  only at enrollment or handshake time.
- **Kernel 1.0** — Proof-of-possession renewal MUST use production-hardened
  transport (today's signed lease-renewal transport is not yet hardened
  for that).
- **Kernel 1.0** — Kernel identity behavior (for example
  `GET /v1/kernel-identity`) MUST remain correct when multiple kernel
  replicas are running.
- **Kernel 1.0** — Key rotation and identity lifecycle administration MUST
  support richer operations than today's generate-once-per-process model.
- **Kernel 1.0** — Instance reconciliation and recovery behavior MUST be
  hardened for production failure modes.

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
  request/route/claim handlers behind the middleware.
- Complete: `POST /v1/instances/renew`, letting an enrolled instance
  extend its own lease before it expires via compare-and-set revision
  matching, reusing the ordinary governed-request gate for authentication
  (see the gap note below for why this was added).
- Future Kernel: not started — production-hardened proof-of-possession
  renewal transport (today's signed lease-renewal transport is not yet
  hardened for that); correctness under multiple kernel replicas for
  `GET /v1/kernel-identity`; continuous (not just enrollment-time)
  service-instance discovery; richer key rotation/lifecycle
  administration; and hardened instance reconciliation/recovery behavior
  (see [Section 8](#8-future-kernel-kernel-10)).
- **Gap found by live testing (2026-08-30, infernal-librarian-simple's own
  live vertical-slice run), fixed the same day:** the "signed
  lease-renewal transport" note above is about hardening
  `kernel::handshakes`, which is the *kernel* challenging a push-delivery
  subscriber — not a route a *client* instance can call to renew its own
  lease before `DEFAULT_LEASE_SECONDS` (60s) expires. No such route
  existed. Concretely: every reference service that polls
  (`infernal-taskmaster-simple`, `infernal-worker-simple`,
  `infernal-librarian-simple`) started failing every signed call with 401
  once it had been running for about a minute, and recovering required a
  full process restart plus a fresh operator-issued enrollment challenge.
  This was a real ILK-001 gap distinct from the push-handshake item above.
  Fixed by adding `POST /v1/instances/renew` as an ordinary governed
  route: it extends the *calling* instance's own lease (identity taken
  from the caller's already-verified signed request, never a body field),
  via the compare-and-set `InstanceRegistryService::renew` method that
  already existed in the domain layer but was unreachable over HTTP.
  Verified live: `infernal-librarian-simple`'s `KernelClient::renew_lease`
  renews proactively (`RENEWAL_MARGIN_SECONDS` before expiry) and ran for
  several minutes with zero 401s across five renewals. This only helps a
  process that performs its own enrollment at startup, which is how every
  current reference service is deployed; an identity enrolled some other
  way still has no way to discover its own current lease state to renew
  from.

See the [direct service protocol](direct-service-protocol.md) and
[ADR-0003](decisions/0003-direct-signed-service-rest.md).
Instance key and discovery lifecycle is specified by
[ADR-0005](decisions/0005-use-ephemeral-per-instance-service-keys.md).

### ILK-002: Authority

**Scope: Split.**

**MVP**: everything needed to authorize steps 3–6 of the vertical slice: a
real allow/deny decision from the external evaluator for request
acceptance, fail-closed on denial or evaluator failure, and durable,
version-pinned decision recording.

**Kernel 1.0**: a second, destination-scoped authority decision that
separately re-authorizes a route before it is exposed, claimed, or
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
- **Kernel 1.0** — Route authority MUST separately consider the
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
- **MVP** (mechanism) / **Kernel 1.0** (administrative UI) — Only an
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
  exposure/claiming is Kernel 1.0.

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
  request-acceptance case; the destination-specific case is Kernel 1.0,
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
  calls this function directly. Both functions were first actually
  exercised against live PostgreSQL only when this repository's kernel
  was deployed and tested in a real Kubernetes cluster, which surfaced
  and fixed two bugs invisible to every prior (in-memory or never-run)
  test: `set_authority_schema_status` declared a PL/pgSQL variable named
  `current_schema`, a reserved identifier PostgreSQL parses as its own
  built-in construct (like `current_user`), breaking on the first real
  invocation; and the Rust query for `publish_authority_schema_version`
  read its result with `SELECT *`, returning raw `uuid`-typed columns
  where every other query in the file casts IDs to `::text` first.
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
  (see [Section 8](#8-future-kernel-kernel-10)).
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
- Kernel 1.0: wiring `PolicyFacts::for_route` into an actual
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
retry, rejection of ID reuse for different content, idempotent
materialization of inclusive routes for actively-matching subscriptions,
and a destination-scoped read of the request behind a route (all Complete
— the last of these closed a real MVP gap; see the implementation status
below).

**Kernel 1.0**: correlation/causation relationships (full realization is
[ILK-005](#ilk-005-relationships)), exclusive-group routes and
consumer-group semantics, append-only route transition history, and
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
  time. (Correlation metadata is Kernel 1.0 — see ILK-005.)
- **MVP** — A request MUST NOT name or expose a concrete destination
  service. The kernel derives destination routes only from authorized
  matching subscriptions.
- **MVP** — Request acceptance and durable storage MUST NOT depend on a
  matching active subscription, reachable destination instance, current
  health, or available delivery capacity.
- **MVP** — A request without an eligible matching subscriber MUST remain
  durably unrouted; it MUST NOT be rejected or silently discarded merely
  because no subscriber exists yet.
- **MVP** (inclusive) / **Kernel 1.0** (exclusive) — A matching
  subscription MUST materialize at most one exclusive route for the
  request/consumer group or one inclusive route for the request/stable
  destination. Those unique keys MUST make repeated scans, retries, and
  subscription wakeups idempotent.
- **MVP** — One request MAY have routes to many destination services.
  **Kernel 1.0** — every route MUST have its own append-only transition
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
- **MVP** — The route's own destination service MUST be able to read
  enough of the request (action, scope, schema references) to actually
  perform the work it claimed, without gaining any broader ability to
  read requests it is not the destination of.
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
- A route's destination service can read the request it was routed for,
  and no other service's requests. **MVP** — proven
  (`returns_the_request_for_the_routes_own_destination`,
  `hides_a_route_owned_by_another_service_as_not_found`).
- A request accepted before its matching subscription exists becomes
  eligible for delivery after that subscription is committed, without
  source resubmission. **Kernel 1.0** (backlog matching — not implemented;
  MVP requires the subscription to already be active at submission time).
- A subscription-creation race cannot lose a matching pending request or
  create more than one accepted request record. **Kernel 1.0**, coupled to
  backlog matching above.
- Two matching destination services produce two independently tracked
  routes; completing either route leaves the other route eligible for
  work. **MVP** (proven for inclusive routes today).
- Replaying backlog scans or wakeups cannot create duplicate work for an
  existing exclusive-group or inclusive-destination route. **MVP** for
  inclusive; **Kernel 1.0** for exclusive-group.

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
  request's own action, scope, and schema versions.
- Complete: `GET /v1/requests/{id}` reads back only the caller's own
  accepted request when the caller is the *source* — another service's
  request looks identical to one that does not exist.
- Complete (first slice — this is the MVP-required piece): `Route`,
  `RouteRepository`, and `RouteService` (`src/kernel/requests.rs`) — an
  accepted request's independent, idempotently-materialized destinations,
  one per matching active inclusive subscription (ILK-010). No delivery
  state, transition history, or work claim exists on a route itself — it
  records only that a destination is eligible; a route's own claim history
  (ILK-011) is what currently stands in for transition evidence.
- Complete: `RouteRepository::find` (a single route lookup by ID) plus
  `GET /v1/routes/{route_id}/request` (`RoutedRequestQuery` in
  `src/http.rs`, composing `RouteService::find` with
  `RequestService::find`) — this is what closes the "worker receives
  governed work" gap this document's previous revision identified.
  `RoutedRequestQuery` resolves a route to the request behind it only for
  the route's own destination service; a route belonging to another
  service, or that does not exist, is indistinguishable to the caller, the
  same convention used for claiming. No separate ILK-002 authority
  decision gates it, matching every other read gated by structural route
  ownership. Proven at the domain level
  (`tests/route_materialization_contract.rs::find_returns_a_single_route_by_id_or_none_for_an_unknown_id`),
  at the HTTP level (colocated `routed_request_routes` tests in
  `src/http.rs`), and against live PostgreSQL
  (`tests/postgres_route_repository.rs`).
- Kernel 1.0: correlation relationships, exclusive-group routes and their
  consumer-group semantics, route transition history, and
  subscription-triggered backlog routing (a subscription committed after a
  request does not yet retroactively see it).

### ILK-004: Versions

**Scope: MVP Kernel** — the append-only/immutability invariant is
load-bearing for the vertical slice (schema version pinning, decision
pinning) and is already true by construction wherever it is exercised.
Administrative lifecycle *workflow* (as opposed to the underlying
immutability) is external tooling — see [ILK-002](#ilk-002-authority).

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

**Scope: Future Kernel — the entire capability.** Nothing here is
implemented, and the MVP vertical slice does not require it (no step needs
correlation/causation querying). Full text preserved in
[Section 8](#8-future-kernel-kernel-10).

### ILK-006: Artifacts

**Scope: Future Kernel + domain-owned by default — the entire capability.**
`Request` does not carry artifact content, an artifact ID, or a payload
reference today — only the schema *version reference* used for authority
(which is ILK-002's responsibility, already MVP-complete). Actual artifact
content mediation is not required by the vertical slice. Full text
preserved in [Section 8](#8-future-kernel-kernel-10); the ownership
question (kernel-owned governed evidence vs. domain-owned content) is
discussed fully in [Section 11](#11-namespace-data-and-search-ownership).

### ILK-007: Decisions

**Scope: Split.**

**MVP**: the authority decision is the one kernel decision type the
vertical slice actually needs, and it already satisfies the shape this
capability describes (durable record, type, outcome, responsible party,
request ID, time, security/schema revisions — see `AuthorityDecision` and
`AuthorityDecisionRecorder` under ILK-002).

**Kernel 1.0**: a generalized, first-class `Decision` record type spanning
routing, pause, and assignment decisions uniformly. Today, route and
work-claim state changes are their own append-only tables
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
  authority decisions; **Kernel 1.0** for a generalized type covering
  routing/work decisions too.
- Reversal or supersession MUST create another decision linked to the
  earlier record.

Acceptance criteria:

- A caller can reconstruct why a request was admitted, denied, routed,
  paused, delivered, or assigned using recorded inputs and policy
  versions. **MVP** for admit/deny; **Kernel 1.0** for a uniform routed/
  paused/delivered/assigned reconstruction API (today this evidence is
  reconstructable by joining `request_routes` and `work_claims`, not
  through one generalized decision query).
- Reversing an administrative or routing decision leaves the earlier
  decision available.
- Adding a service-specific business outcome does not require adding a
  kernel decision enum variant.

### ILK-008: Audit

**Scope: MVP Kernel** — the minimum audit evidence needed to reconstruct
the vertical slice already exists, spread across each capability's own
append-only table (replay audit, admission audit, authority decisions,
subscription history, route/claim status history). A single unified audit
log across all capabilities, including ones that are themselves Future
Kernel (artifact mediation, events), is Kernel 1.0.

Invariants:

- Security and governance actions MUST append an audit record in the same
  successful transaction as their governed state change.
- Audit records MUST NOT be updated or deleted through kernel contracts.
- Each record MUST include its event type, request ID where applicable,
  source service, instance and key, namespaced action, artifact and
  permission schema versions, administrative revision, time, outcome, and
  correlation ID (correlation ID is Kernel 1.0 — see ILK-005). Route
  records additionally include destination service and subscription.
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

**Scope: Future Kernel — the entire capability.** Unimplemented; the
vertical slice does not publish or consume typed events. Full text
preserved in [Section 8](#8-future-kernel-kernel-10).

### ILK-010: Subscriptions

**Scope: Split.**

For `v0.1.0`, a subscription is the minimum durable declaration required
for one service to express interest in governed Requests without the
Request source knowing that service exists.

**MVP**: create/list/disable of inclusive subscriptions, matching against
subscriptions already active at submission time, and idempotent route
materialization (all Complete today).

**Kernel 1.0**: exclusive consumer groups, `all_of` state selectors,
backlog matching, durable delivery cursors, route transition history, and
hardened production outbound handshake transport.

**External infrastructure**: capacity-aware delivery, worker/node
placement, and retry-timing policy belong to Taskmaster, not the kernel —
see [ADR-0011](decisions/0011-move-scheduling-policy-outside-the-kernel.md)
and [Section 9](#9-external-infrastructure-services).

- Implementation: `src/kernel/subscriptions.rs`
- Independent contract test: `tests/subscription_contract.rs`

MVP invariants:

- **MVP** — A service MUST be able to create, inspect, and disable its own
  subscriptions through authenticated kernel contracts.
- **MVP** — An MVP subscription MUST identify its stable owning service.
- **MVP** — An MVP subscription MUST identify the approved namespaced
  Request/action contract it accepts.
- **MVP** — An MVP subscription MUST use inclusive delivery semantics; an
  omitted or unknown mode MUST fail closed.
- **MVP** — A matching active subscription MUST cause the kernel to
  idempotently materialize at most one route for the `(request,
  destination service)` pair. (Enforced today by two invariants together:
  materialization is keyed by `(request_id, subscription_id)`, and a
  unique index permits at most one active subscription per `(service,
  event_type)` — so at most one subscription, and hence at most one
  route, can match a given request for a given destination.)
- **MVP** — Disabling a subscription MUST prevent it from matching future
  Requests without deleting its prior definition or routing history.
- **MVP** — Subscription creation and disable operations MUST be
  authorized and auditable.
- **MVP** — A source service MUST NOT learn which subscriptions,
  destination services, or runtime instances matched its Request.

The MVP does NOT require:

- exclusive consumer groups;
- consumer-group identities;
- generalized selectors;
- predicate sets;
- `all_of` semantics;
- durable backlog cursors;
- replay scanning;
- subscription-triggered routing of pre-existing Requests;
- sophisticated routing windows;
- capacity-aware delivery;
- production-hardened subscriber discovery.

Those capabilities are classified separately as Future Kernel or External
Infrastructure responsibilities, detailed as invariants below and in
[Section 8](#8-future-kernel-kernel-10):

- **Kernel 1.0** — An exclusive subscription MUST declare an approved
  consumer-group identity. All services in that group compete for one
  request/group route and one completion; failover reassigns that route
  rather than resubmitting the request.
- **Kernel 1.0** — A subscription MAY require multiple typed state
  predicates. The minimum semantics MUST be `all_of`, evaluated from one
  consistent committed snapshot; every predicate must be true before a
  route becomes eligible. (Kept as a small deterministic declarative
  mechanism over trusted committed state — not a business rules engine;
  see [Section 11](#11-namespace-data-and-search-ownership).)
- **MVP** — Subscription modes, group identities, selectors, predicate
  sets, referenced schema versions, and routing-window policies MUST be
  immutable after creation. Replacement creates a new version and
  preserves the old definition.
- **MVP** — Selector predicates MUST be declarative approved fields and
  fixed operators; caller-supplied SQL, code, database identifiers, and
  executable expressions are forbidden.
- **Kernel 1.0** — Committing a subscription MUST make pre-existing
  matching pending requests eligible for routing; subscription timing MUST
  NOT determine whether a request is retained. (This is backlog matching —
  MVP's vertical slice requires the subscription to already be active
  before the request is submitted.)
- **MVP** — The subscription registry supplies eligible destination
  services; it MUST NOT be overwritten with route progress or work
  history. **Kernel 1.0** — a durable wakeup cursor (today, matching is a
  simple active-set query, not a cursor-based scan).
- **Kernel 1.0** — The kernel MUST use a durable subscription cursor or
  equivalent wakeup marker to find both new and pre-existing matching
  requests without loss.
- **External infrastructure** — Pausing or deferring delivery for
  readiness, health, or capacity reasons is scheduler policy (ADR-0011)
  and MUST NOT delete or disable durable subscription state.
- **Kernel 1.0** — Every kernel instance MUST continuously discover
  reachable instances for active subscriptions and complete a fresh,
  mutual proof-of-possession handshake before delivering to an instance.
  (The discovery/handshake mechanism exists; production-hardened outbound
  transport is the remaining piece.)

These Kernel 1.0 extensions MUST NOT turn subscriptions into a general
business-rules language. Business-domain eligibility and reasoning remain
domain-service responsibilities.

Acceptance criteria:

- A service receives or can retrieve only requests or events matching its
  active subscriptions, destination, approved schemas, and authorization
  scope. **MVP.**
- With no matching subscription, an accepted request remains durably
  pending. Creating an eligible matching subscription later exposes that
  backlog to the subscriber without requiring the source to retry or know
  the subscriber's runtime identity. **Kernel 1.0** (backlog matching).
- The kernel's eligibility query returns incomplete routes filtered by
  active subscription, authorization, and handshake state, excluding
  completed routes and routes protected by an active work claim.
  Taskmaster may prioritize eligible work; an eligible worker claims the
  route under its own authenticated identity. Readiness and capacity are
  scheduler policy inputs, not kernel filters (see
  [ADR-0011](decisions/0011-move-scheduling-policy-outside-the-kernel.md)).
  **MVP — done for the minimum shape**: `GET /v1/routes/eligible`
  (`EligibleRouteQuery`, composing ILK-003's `list_for_destination` with
  ILK-011's `active_route_ids` and `completed_route_ids`) returns the
  caller's own materialized routes that have no current, unexpired active
  claim and have never been completed. The completed-route exclusion was
  a real, confirmed-live gap until fixed: `active_route_ids` alone only
  ever looked at whether a claim was *currently* active, and a completed
  claim is neither active nor absent, so a completed route looked exactly
  like a plain unclaimed one and stayed eligible forever. It does not
  re-check subscription-active or handshake state at query time (a route
  only exists because both were true at materialization time) — doing so
  is a **Kernel 1.0** refinement, not a gap in the query existing at all.
- If an exclusive destination instance or service fails, its assignment
  lease expires and the same route can be fenced and reassigned to
  another eligible service in the consumer group. No new request is
  created. **Kernel 1.0** (exclusive groups); the underlying fence/lease
  mechanism is MVP-complete for the inclusive case (ILK-011).
- A stale worker cannot renew, release, or complete a reassigned route
  because every mutation requires the current fencing token. **MVP**
  (proven for work claims today; "route revision" and "assignment ID" as
  separate concepts from the fencing token are Kernel 1.0 — see ILK-011).
- Concurrent evaluation produces at most one exclusive request/group route
  or one inclusive request/destination route. Exactly one active
  assignment, one active claim, and one successful completion may exist
  per route. **MVP** for inclusive; **Kernel 1.0** for exclusive-group.
- The selector version and state revisions used for each eligibility
  decision remain queryable; later state mutations do not rewrite prior
  decisions. **Kernel 1.0** (coupled to `all_of` selectors).
- Disabling a subscription prevents new deliveries without deleting its
  history. **MVP.**
- A scheduler deferring claims for saturation, stale health, or lack of
  capacity does not advance or lose the durable cursor; resumed claiming
  picks up from the same eligible set (ADR-0011). **External
  infrastructure** — the eligible-route query it reads is MVP-complete;
  the deferral/retry policy itself is Taskmaster's, not the kernel's.
- One unreachable subscriber does not prevent kernel startup or discovery
  of other subscribers; its delivery remains paused and is retried with
  backoff. **Kernel 1.0** (production handshake transport hardening).

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
- Complete (this is MVP): the eligible-route query external scheduler
  services use (ADR-0011) — `GET /v1/routes/eligible`, backed by
  `EligibleRouteQuery` in `src/http.rs`. See ILK-011's own status below
  for the composition and its tests.
- Kernel 1.0: exclusive delivery with consumer groups, immutable `all_of`
  state selectors, backlog matching (a subscription committed *after* a
  request currently never finds it — only subscriptions active at
  submission time are considered), route transition history, delivery
  cursors, and production outbound handshake transport.
- External infrastructure: capacity-aware delivery, worker/node placement,
  and retry-timing policy. Those belong to an external scheduler service,
  not the kernel (ADR-0011) — see
  [Section 9](#9-external-infrastructure-services).

### ILK-011: Work claims

**Scope: Split.**

**MVP**: atomic claim/renew/release/complete with lease and fencing, one
active claim per route, and the minimal eligible-route query a scheduler
needs to find something to claim (all Complete).

**Kernel 1.0**: administrator-authorized forced claim revocation (only
expiry, release, and completion exist today — no admin-forced revoke), and
distinguishing "route revision" and "assignment ID" from the fencing token
as separate concepts (today deliberately conflated: the fencing token
alone identifies the current claim).

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
- **MVP** (fencing token) / **Kernel 1.0** (route revision, assignment ID
  as distinct fields) — A claim MUST be bound to the route revision,
  assignment ID, worker service and instance, lease, and monotonically
  increasing fencing token.
- **MVP** — Route reassignment MUST occur only after atomic release,
  expiry, or an authorized revocation transition. Liveness observations
  alone MUST NOT silently transfer ownership. (Authorized *administrative*
  revocation specifically is Kernel 1.0; expiry and release are MVP.)

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
  exist), as `AlreadyClaimed` if a current, unexpired claim exists, and as
  `AlreadyCompleted` if the route's latest claim already reached the
  terminal `Completed` status — checked independent of lease timing, since
  a route's completion is permanent and a completed claim would otherwise
  look identical to an ordinary expired one once enough time passed
  (confirmed live: without this check, a completed route was reclaimable
  indefinitely). Otherwise it supersedes whatever claim previously
  existed.
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
- Complete: the eligible-route query — `GET /v1/routes/eligible`, backed
  by `EligibleRouteQuery` in `src/http.rs`. It composes
  `RouteRepository::list_for_destination` (ILK-003) with
  `WorkClaimRepository::active_route_ids` and `completed_route_ids`
  (ILK-011, bulk "which of these routes have a live claim" and "which of
  these routes have ever been completed" reads) without either kernel
  module depending on the other's repository — the same compositional
  pattern `SubscriptionRouter` uses to bridge ILK-010 and ILK-003. Both
  exclusions are required: confirmed live, `active_route_ids` alone left
  a completed route eligible forever, since completion is neither
  "active" nor absent from claim history the way an ordinary lease
  expiry is. The destination queried is always the caller's own verified
  identity, never a request parameter, so a caller can only ever see its
  own eligible routes; it
  requires no separate ILK-002 authority decision, matching every other
  read of the caller's own data (`GET /v1/subscriptions`,
  `GET /v1/requests/{id}`). Proven at the domain level
  (`tests/route_materialization_contract.rs`,
  `tests/work_claim_contract.rs`, `tests/postgres_route_repository.rs`,
  `tests/postgres_work_claim_repository.rs`) and at the HTTP level
  (colocated `eligible_route_routes` tests in `src/http.rs`), including
  that a route with an expired claim becomes eligible again and that a
  caller never sees another service's routes. This query tells a
  scheduler/worker *that* a route exists to claim; ILK-003's
  `GET /v1/routes/{route_id}/request` (see above) tells the worker *what*
  the request behind it is, closing what was previously an open gap.
- Kernel 1.0: administrator-authorized forced claim revocation;
  route-revision/assignment-ID distinctness (currently conflated with the
  fencing token as a deliberate simplification).
- External infrastructure: any scheduling policy (which eligible route a
  worker should claim next, priority, capacity) — deliberately out of
  kernel scope (ADR-0011). `infernal-taskmaster-simple`'s FIFO scheduler
  calls the eligible-route query and proposes claims against it, and
  `infernal-worker-simple` now claims its own eligible work directly,
  reads the request behind it, and completes it — a route can only ever
  be claimed and completed by the same authenticated caller (`claim`
  takes `worker_service`/`worker_instance` from the caller's own verified
  identity, never a body field), so a worker performs this whole loop
  itself rather than executing a claim a separate scheduler process
  proposed. Both reference services' own signing/parsing/policy logic is
  tested independent of a live kernel — see
  [Section 7](#7-current-mvp-implementation-status).

### ILK-012: Idempotency

**Scope: Split.**

**MVP**: request-level idempotency, which is exactly what ILK-003's
request-ID/fingerprint binding and safe-retry classification already
provide (there is no separate ILK-012 implementation — this capability is
realized entirely through ILK-003's mechanics).

**Kernel 1.0**: idempotency for mediated artifact writes and promised
events, which cannot exist before their underlying capabilities (ILK-006,
ILK-009) do.

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
  **Kernel 1.0** for the artifact write and promised event (ILK-006/009 do
  not exist yet).
- A key collision with a different payload returns a deterministic
  conflict. **MVP** — proven (`request_id_cannot_be_rebound_to_another_action_or_fingerprint`,
  `request_id_cannot_be_rebound_to_different_semantic_content`).

### ILK-013: Mediation

**Scope: MVP Kernel** — structural invariant, true by construction across
every kernel module (every repository trait uses fixed statements and
typed parameters; nothing accepts caller-supplied SQL). No further work is
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

## 6. MVP failure/recovery acceptance tests

The MVP MUST prove:

| Required proof | Test(s) | Status |
| --- | --- | --- |
| Retrying the same semantic Request does not create duplicate work | `acceptance_is_durable_through_the_repository_contract_and_safe_to_retry`, `concurrent_acceptance_has_one_fresh_result_and_no_duplicate_record`, `same_request_with_a_new_signature_is_a_safe_idempotency_retry` | Done |
| Reusing a Request ID for different content fails deterministically | `request_id_cannot_be_rebound_to_another_action_or_fingerprint`, `request_id_cannot_be_rebound_to_different_semantic_content` | Done |
| An unauthorized Request fails closed | `default_deny_when_no_grant_matches` | Done |
| An unavailable, malformed, or erroring policy evaluator fails closed | `unreachable_evaluator_is_denied_never_implicitly_allowed` | Done |
| Concurrent claims produce exactly one valid owner | `concurrent_claim_attempts_on_the_same_route_produce_exactly_one_active_holder` | Done |
| An expired claim can be acquired by another worker | `another_worker_can_claim_after_the_prior_lease_expires` | Done |
| A stale worker cannot complete after fencing/reassignment | `a_stale_holder_cannot_renew_release_or_complete_after_losing_its_claim` | Done |
| Kernel restart does not lose accepted Requests, routes, claims, authority decisions, or required audit state | `tests/postgres_request_repository.rs`, `tests/postgres_route_repository.rs`, `tests/postgres_work_claim_repository.rs`, `tests/postgres_authority_repository.rs` (all ignored, live-DB); `tests/vertical_slice_continuity_contract.rs` (ignored, live-DB) | Done. Every `#[ignore]`d live-Postgres test in the repo has been executed against a real PostgreSQL instance and passes, run individually as documented. `vertical_slice_continuity_contract.rs` closes the one remaining gap: submit, materialize, eligible-route query, claim, retry, read, complete, and a real reclaim/fencing race are now proven chained across one request's whole lifetime — including a real kernel restart (drop and reconnect `Application`) mid-scenario — not just per-repository |

Do not require unrelated generalized features before tagging the MVP: none
of these proofs depend on exclusive delivery, `all_of` selectors, artifact
content mediation, or events.

## 7. Current MVP implementation status

Every MVP-scoped portion of Section 5 is Complete and requires no further
work for `v0.1.0` — most of these ILKs are tagged **Split** there, not
bare **MVP Kernel**, so "Complete" here means their MVP portion
specifically, not that nothing about them is Kernel 1.0: ILK-001's
identity/instance/signing/replay/attribution invariants (Split —
production identity lifecycle hardening is Kernel 1.0), ILK-002's
request-acceptance authority (Split), ILK-003's immutable requests,
inclusive route materialization, and destination-scoped request read
(`GET /v1/routes/{route_id}/request`) (Split), ILK-004 (MVP Kernel, in
full), ILK-007's authority-decision evidence (Split), ILK-008's
per-capability audit (MVP Kernel, in full), ILK-010's inclusive
subscriptions (Split), and ILK-011's claim/renew/release/complete with
fencing *and* the eligible-route query (`GET /v1/routes/eligible`)
(Split).

Every kernel capability the vertical slice needs is now code-complete.
`infernal-taskmaster-simple`'s FIFO scheduler calls the eligible-route
query and proposes claims; `infernal-worker-simple` claims its own
eligible work, reads the request behind it, and completes it — both
reference services' signing, parsing, and policy logic are proven
independent of a live kernel connection, in their own repositories.

The kernel, `infernal-inquisitor-simple`, `infernal-taskmaster-simple`,
and `infernal-worker-simple` have all been built as containers, deployed
together into a real Kubernetes cluster, and exercised there. That pass
found and fixed two real bugs in `set_authority_schema_status`/
`publish_authority_schema_version` — a reserved-identifier collision
(`current_schema`, a PL/pgSQL built-in like `current_user`) and a raw
`uuid`-typed column read where every other query in the file casts to
`::text` — both invisible until this was the first time either function
actually ran against real PostgreSQL. It also confirmed, directly, all 13
`#[ignore]`d live-Postgres test files pass individually (the documented
usage), and that `infernal-taskmaster-simple`/`infernal-worker-simple`
start, configure correctly, and log a clear transport error rather than
crashing when their signed calls can't complete — because
`infernal-client-rs`'s `SignedRequest` always dials
`https://<authority>`, while `infernal-law`'s own Kubernetes `Service`
did not terminate TLS. A TLS-terminating layer in front of the kernel was
a real, confirmed requirement for those two services to actually complete
a call, not merely attempt one — deployment infrastructure, not a kernel
code gap.

That gap has since been closed: an nginx sidecar now terminates TLS in
the kernel's own Pod, exposed as the Kubernetes `Service`'s `https` port
(see the [Kubernetes section of the README](../../README.md#kubernetes)).
Getting a real signed call through it end to end surfaced two further
deployment-only bugs, both fixed and reverified against the same kind
cluster: the proxy's default upstream HTTP version (1.0) was rejected by
the kernel's minimal parser, which requires exactly `HTTP/1.1`; and a
self-signed certificate generated without explicit `CA:FALSE` and
`subjectAltName` extensions defaults to looking like its own CA with no
usable hostname, which `rustls` (`infernal-client-rs`'s TLS backend)
rejects outright as `CaUsedAsEndEntity`. With both fixed,
`infernal-taskmaster-simple` and `infernal-worker-simple` now complete
real signed HTTPS calls to the kernel through the sidecar and receive its
correct, well-formed `401` for an identity that is not yet enrolled —
proving the entire transport/HTTP/signature-verification pipeline works,
with only the enrollment step itself remaining as genuine infrastructure,
not code.

That has since been completed too: `infernal-client-rs` now implements
ADR-0008's candidate side (`EnrollmentSubmission`,
`Client::submit_enrollment`), proven wire-compatible with the kernel's own
`EnrollmentService` by a dedicated cross-crate test
(`tests/enrollment_wire_compatibility.rs`), and both reference services
perform it at startup when configured with a challenge. Running that for
real against the same kind cluster — the only time `/v1/enrollments` has
ever been exercised end to end — found and fixed one more real bug: the
kernel's own `kubernetes-reviewer` projected volume mounted `ca.crt` at
mode `0400` owned by `root`, unreadable by the container's own non-root
user, so `KubernetesTokenReviewer::from_env()` failed closed with a
generic "enrollment could not be completed" every time (fixed with
`fsGroup: 65532` in the kernel's Pod `securityContext`). It also surfaced
that a signed call passing authentication still needs its identity's
`service_communication_admission` row explicitly enabled (ILK's
communication-admission gate, administered the same out-of-band way as
grants and schema activation) before any governed route — including
`GET /v1/routes/eligible` — will do anything but `403`.

With both fixed and a real challenge issued out-of-band (there is no
self-service HTTP call for requesting one — see
`infernal_client::EnrollmentSubmission`'s own documentation for why),
`infernal-taskmaster-simple` and `infernal-worker-simple` completed a real
ADR-0008 enrollment against the live TokenReview API, then polled
`GET /v1/routes/eligible` successfully and continuously with no further
authentication or admission errors. This is the first time any of
signature verification, TokenReview, challenge consumption, communication
admission, and instance registration have all been proven together
end to end.

What remains before tagging `v0.1.0` is finishing that validation, not new
capability:

1. ~~Complete real ADR-0008 Kubernetes TokenReview enrollment for the
   reference services' identities~~ — **done and verified above.**
2. ~~Close any remaining transaction/idempotency gaps exposed by that
   end-to-end path~~ — **done.** `tests/vertical_slice_continuity_contract.rs`
   proves acceptance, materialization, the eligible-route query, claiming,
   a safe retry, the destination-scoped read, and completion all hold
   together against live PostgreSQL in one request's lifetime, including a
   real kernel restart (dropping and reconnecting `Application`) partway
   through.
3. ~~Run the required retry, denial, crash/recovery, concurrency, and
   fencing tests as one continuous scenario~~ — **substantially done.**
   The same test chains retry, crash/recovery (restart), and reclaim/
   fencing (a second worker instance reclaiming an expired lease, then the
   original holder's stale token failing to renew/release/complete)
   together. Denial and same-route concurrent-claim racing are deliberately
   *not* re-proven there: both already have their own dedicated,
   independent live/unit proofs (`default_deny_when_no_grant_matches`,
   `unreachable_evaluator_is_denied_never_implicitly_allowed`,
   `concurrent_claim_attempts_on_the_same_route_produce_exactly_one_active_holder`),
   and ILK-002 denial specifically lives at the HTTP layer (the evaluator
   call), one layer above where this chained test deliberately operates
   (see that test file's own module documentation for why) — composing
   them in too would duplicate coverage without adding a new chained
   proof, not close a real gap.
4. ~~Nothing in this ecosystem yet performs a real signed
   `POST /v1/requests` end to end~~ — **done and verified above.** A
   one-off enrolled test identity submitted a real signed request through
   the full live stack (TLS, ADR-0008 enrollment, ILK-002 authority via a
   real Inquisitor call, materialization, claim, reclaim after lease
   expiry, fencing, completion, and a kernel restart partway through) and
   Postgres showed exactly the expected end state: one request, one
   route, a two-entry claim history (one expired, one completed), and
   full audit/decision evidence. This is also what closed two further
   real gaps, both fixed and reverified: the kernel's own outbound
   ADR-0013 evaluator call needed the same TLS treatment as its inbound
   listener (`infernal-inquisitor-simple` now runs the same tls-proxy
   sidecar), and `POLICY_EVALUATOR_AUTHORITY`/`POLICY_EVALUATOR_ID` were
   never actually present in the tracked kernel manifest, only ever set
   ad hoc during live testing.

   This same exercise also found a genuine correctness bug, since fixed:
   a completed route was reclaimable *indefinitely*. With nothing
   competing for it, a worker reclaimed and re-completed the same
   already-completed route repeatedly, minting a new, strictly higher
   fencing token each time, directly contradicting ILK-010's own
   "excluding completed routes" requirement and ILK-011's single-
   completion invariant. `WorkClaimRepository::claim` now rejects any
   further claim once a route's latest claim is `Completed`, independent
   of lease timing, and the eligible-route query excludes completed
   routes via a new `completed_route_ids` alongside `active_route_ids`.

See the [completion checklist](#remaining-work-before-v010-minimum-viable-kernel)
at the end of this document for the same list in one place.

Nothing else is required to tag `v0.1.0`. In particular: exclusive
consumer groups, `all_of` selectors, backlog matching, route transition
history, correlation/causation, artifact content mediation, typed events,
and any scheduling policy are all explicitly out of scope for `v0.1.0` —
see Section 8.

## 8. Future Kernel / Kernel 1.0

These remain legitimate, permanent kernel responsibilities — they protect
authority, communication, or correctness — but none of them block
`v0.1.0`. Items already covered inline under their `ILK-*` section in
Section 5 are cross-referenced rather than repeated; capabilities that are
deferred in their entirety are given in full here.

Cross-referenced (see Section 5 for full invariants/acceptance criteria):

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
  route revision and assignment ID as distinct from the fencing token;
  generalizing the eligible-route query (`GET /v1/routes/eligible`) with
  pagination, an explicit worker-class/capability declaration distinct
  from destination identity, and richer freshness/staleness semantics
  than a plain committed read (ADR-0011 open decision).
- **ILK-012** — idempotency for mediated artifact writes and promised
  events, blocked on ILK-006 and ILK-009 existing first.
- **Multi-replica kernel correctness** — `GET /v1/kernel-identity` behind
  multiple replicas remains an open follow-up (ADR-0014). Per the
  boundary rule, load-balancing/discovery across replicas is
  infrastructure, but identity, fencing, and proof-of-possession
  correctness across replicas remain kernel responsibilities.

### Specific edge classifications

A quick-reference index into the detail above and in
[Section 11](#11-namespace-data-and-search-ownership):

| Topic | Classification | Why |
| --- | --- | --- |
| Exclusive consumer groups | Future Kernel | Exactly-one route/ownership semantics are a correctness guarantee and belong in the kernel, but inclusive delivery is sufficient for the first MVP — see ILK-010. |
| `all_of` state selectors | Future Kernel | A deliberately small, deterministic, declarative eligibility mechanism over trusted committed state. It MUST NOT become a general business-rules engine — business rules belong to a domain service such as a Parametric Rules Service. |
| Subscription cursors | Kernel responsibility where needed for durable no-loss/no-duplicate routing; sophisticated cursor/replay semantics are Future Kernel. | ILK-010's simple active-set match is enough for MVP; a durable wakeup cursor is not. |
| Relationships | Split. | Universal communication relationships (correlation, causation, retry, response, routing, delivery, work origin) may be kernel-owned (ILK-005, Future Kernel); domain-specific relationships belong to the domain service. |
| Artifact storage | Domain-owned by default. | The kernel owns governance metadata, integrity evidence, authorization, routing, and mediation of cross-service access — never a universal artifact/blob database. See Section 11. |
| Search | Domain-owned for domain data; kernel-owned only for kernel state. | Kernel search is limited to Requests, routes, subscriptions, authority decisions, claims, and audit records. See Section 11. |
| Schema lifecycle | Split. | Security-relevant activation/status/grants remain kernel-owned (ILK-002); UI, proposal workflow, or administrative automation may be external. |
| Multi-replica operation | Split. | Infrastructure mechanics (load balancing, Kubernetes placement) should remain external wherever possible; identity, proof-of-possession, fencing, uniqueness, authority, and durable correctness remain kernel responsibilities. |

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
[domain-owned](#10-domain-owned-services), never kernel.

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
mediation/integrity/provenance contract; the artifact content itself is
domain-owned by default and physical byte storage MAY be implemented by an
external storage adapter/service rather than becoming a kernel-hosted
object store — see [Section 11](#11-namespace-data-and-search-ownership).

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

## 9. External infrastructure services

### Taskmaster (external scheduler)

Taskmaster is an ordinary external service. It owns optimization policy:

- priority;
- ordering;
- worker selection;
- node selection;
- CPU/GPU/resource-class placement;
- capacity;
- affinity;
- backpressure;
- retry timing;
- Kubernetes placement;
- health/capacity interpretation.

Taskmaster MUST NOT own:

- authoritative route state;
- eligibility truth;
- work claims;
- fencing;
- durable cursor state;
- authorization;
- final ownership decisions.

The kernel exposes trusted eligible work. Taskmaster proposes what should
run. The kernel atomically decides whether that proposal is still valid.

> **Taskmaster optimizes. Kernel arbitrates.**

The kernel exposes only the trusted state and atomic operations necessary
for Taskmaster to make proposals — the eligible-route query
(`GET /v1/routes/eligible`, MVP-complete) and the claim/renew/release/
complete contract (also MVP-complete) — and remains the final arbiter of
eligibility and ownership. See
[ADR-0011](decisions/0011-move-scheduling-policy-outside-the-kernel.md).
`infernal-taskmaster-simple` is the reference implementation: its FIFO
scheduler signs and sends `GET /v1/routes/eligible` and
`POST /v1/routes/{route_id}/claims` calls using its own long-lived
instance credential, the mirror image of how the kernel signs its own
call to a policy evaluator, and treats a lost claim race (`409`) as an
ordinary outcome, not an error — proven with its own signing/parsing/FIFO
tests, independent of a live kernel connection.
[`infernal-worker-simple`](https://github.com/BenjaminGrandstaff/infernal-worker-simple)
is the reference worker on the other end: because the kernel takes
`worker_service`/`worker_instance` from whichever caller signs the claim
request, never a body field, there is no way for Taskmaster to claim work
and hand it to a different process to complete — so this worker claims
its own eligible work directly rather than executing a proposal
Taskmaster made on its behalf. Both reference services prove the same
contract from different vantage points; validating them together against
a live, enrolled kernel is what remains (Section 7). The scheduling
*logic* itself is never kernel scope.

### Inquisitor (external policy evaluator)

Inquisitor is an ordinary stateless service. It owns only the policy
algorithm:

```text
evaluate(kernel_fact_bundle)
    → allow / deny
    → evaluated policy bundle/version
```

It MUST NOT own authoritative:

- identities;
- grants;
- schema state;
- artifact data;
- route state;
- authorization history.

The kernel owns those facts, sends the evaluator the trusted fact bundle,
records the returned verdict and policy version, and remains the final
enforcement point. Evaluator failure MUST remain denial.

> **Inquisitor evaluates. Kernel knows, records, and enforces.**

See
[ADR-0013](decisions/0013-external-stateless-policy-evaluator-for-authority.md).
`infernal-inquisitor-simple` is the reference implementation and is
already Complete and integrated — no `v0.1.0` work remains here.

### External artifact/blob storage

Physical artifact/blob storage MAY be implemented by an external storage
adapter/service. The kernel should own the governed contract, provenance,
and integrity requirements, and the mediation boundary, rather than
becoming a general-purpose object store itself (ILK-006, Kernel 1.0 — not
required for `v0.1.0`). See
[Section 11](#11-namespace-data-and-search-ownership) for the full
ownership split.

## 10. Domain-owned services

Business semantics MUST remain outside the kernel. A domain service is
authoritative for its own data and semantics, including:

- geometry semantics;
- CAD topology and parametrics;
- engineering requirements;
- documents;
- simulation;
- parametric rules;
- AI reasoning;
- business workflows;
- domain artifacts;
- domain relationships;
- domain databases;
- vector stores;
- graph stores;
- full-text indexes;
- spatial indexes;
- domain search;
- domain mutation validation.

The kernel MAY validate approved schemas and bounded metadata but MUST NOT
grow a universal business-object model. This is the same rule stated in
the kernel object boundary (Section 2): the only general
non-administrative object the kernel defines is a **Request**. Connected
services own the schemas, action vocabulary, artifacts, and
permission-policy vocabulary for their business domains.

A useful conceptual split for artifacts specifically:

> **The service owns the artifact.**
>
> **The kernel owns the governed evidence that the artifact was
> referenced, transmitted, authorized, or acted upon.**

[Section 11](#11-namespace-data-and-search-ownership) works through this
model in detail — how namespaces map to owning services, how
cross-service communication stays kernel-mediated even between two domain
services, and how search and business-workflow ownership follow the same
rule.

## 11. Namespace, data, and search ownership

This section is new architectural guidance, not implementation status: it
records the ownership model the kernel's namespace/schema mechanism is
designed to support, so that adding domain services later (geometry,
requirements, simulation, and so on) does not quietly pull business logic
into the kernel.

### Service-owned data model

A domain service owns the authoritative artifacts in its namespace. For
example:

```text
engineering.*
    → Engineering Service
        → engineering database / object storage / indexes

geometry.*
    → Geometry Service
        → geometry database / spatial indexes / search

requirements.*
    → Requirements Service
        → requirements database / graph / vector index / search
```

The kernel MUST NOT assume that a namespace maps directly to a physical
database. The mapping is:

> **namespace → owning service**

The owning service decides how its data is stored, partitioned,
replicated, indexed, or searched. A service may own relational storage,
object/blob storage, full-text indexes, vector indexes, graph indexes,
spatial indexes, and domain-specific search logic. None of these are
kernel responsibilities.

### Cross-service communication invariant

Domain ownership does NOT permit direct service-to-service communication.
All communication between services MUST remain kernel-mediated. A service
MUST NOT directly call another domain service or directly access another
service's database/index.

For example, a query:

```text
Parametric Rules Service
        |
        | geometry.search Request
        v
      Kernel
        |
        v
Geometry Service
        |
        | query its own DB/index
        v
      Kernel
        |
        | search result
        v
Parametric Rules Service
```

And a mutation, if the rules engine decides a geometry change is needed:

```text
Parametric Rules Service
        |
        | geometry.change Request
        v
      Kernel
        |
        v
Geometry Service
        |
        | validates domain state
        | performs mutation
        | creates new version
        v
      Kernel
        |
        v
Parametric Rules Service
```

The kernel does not understand the geometry query, parameter rule, or
geometry mutation. It authenticates, authorizes, routes, records, and
mediates the request.

### Artifact ownership

Domain services own authoritative artifact content. The kernel may record
bounded artifact metadata needed for governance, such as:

- artifact namespace;
- artifact ID;
- artifact version;
- owning service;
- schema reference/version;
- content digest;
- opaque reference;
- request provenance.

The kernel SHOULD NOT become the general-purpose artifact database (see
[ILK-006](#ilk-006-artifacts)). Cross-service artifact access MUST occur
through a kernel-mediated Request. The artifact-owning service MAY return
content through that governed path, but consumers MUST NOT access the
owner's storage directly.

### Search ownership

The service that owns authoritative domain data also owns search over
that data. Examples:

- Geometry Service owns geometry/spatial search.
- Requirements Service owns full-text/vector/graph search over
  requirements.
- Document Service owns document search.
- Simulation Service owns simulation-result search.

The kernel MAY expose search over kernel-owned state such as Requests,
routes, subscriptions, authority decisions, claims, and audit records. The
kernel MUST NOT implement generalized domain search. The kernel only needs
enough information to authorize and route a search Request, for example:

```text
action: geometry.search
source: parametric-rules
scope: project-123
schema: geometry.search/v1
```

The Geometry Service defines what `geometry.search` means.

### Business workflow ownership

The kernel MUST NOT orchestrate business workflows merely because several
Requests form a sequence. For example, the kernel should not know that:

```text
search geometry
→ evaluate parametric rule
→ propose geometry change
→ regenerate geometry
```

forms one business process. Each service receives governed inputs,
performs its own domain responsibility, and submits subsequent Requests
when needed. The kernel mediates those Requests independently, exactly as
it would mediate any other unrelated Request — it does not track that
they belong to the same business process.

### Namespace scaling rule

Namespaces are ownership boundaries, not physical storage declarations.
Example:

```text
engineering.*
geometry.*
requirements.*
simulation.*
```

Each namespace resolves to an owning service. Larger namespaces can later
be split into more specific ownership boundaries without teaching the
kernel the business meaning. For example:

```text
engineering.geometry.*
engineering.requirements.*
engineering.analysis.*
```

The kernel routes through registered schemas/subscriptions/authority. The
owning services determine their persistence topology.

> **Namespaces define ownership boundaries. Services define persistence
> boundaries.**

## 12. Open design decisions

No contradiction with an accepted ADR was found while producing this scope
reclassification; every reclassification here is a scope label, not a
technical change. ADR-0009, ADR-0011, and ADR-0013 in particular already
anticipated this MVP/Kernel-1.0 split (explicit delivery modes, scheduling
policy moved outside the kernel, and a stateless external evaluator,
respectively) and remain fully consistent with it.

The requirements intentionally do not choose most of these implementation
details. Two are resolved. The eligible-route query's minimum shape
(ADR-0011) is now `GET /v1/routes/eligible`, scoped to the caller's own
verified destination identity, with no pagination and no separate
worker-class declaration (a route's own destination *is* the worker class
for `v0.1.0`'s inclusive-only slice) — deliberately the smallest contract
that unblocks Taskmaster, not a general one. Generalizing it (pagination,
an explicit worker-class/capability declaration distinct from destination
identity, and freshness/staleness semantics beyond a plain committed read)
is Kernel 1.0, tracked alongside exclusive consumer groups in Section 8.
How a claimed route's worker learns the request's content is also
resolved: a separate destination-scoped read,
`GET /v1/routes/{route_id}/request`, rather than embedding request
content in the claim/route response — this keeps `WorkClaimResponse` and
`RouteResponse` about claim/route state only, and reuses
`AcceptedRequestResponse` as-is rather than inventing a second request
wire format. The remaining open decisions:

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

### Remaining work before `v0.1.0 — Minimum Viable Kernel`

Every kernel capability and reference service the vertical slice needs is
code-complete, and the full vertical slice has now been proven live,
end to end, against a real Kubernetes cluster — not just per-capability.
This list is entirely **Done**:

- Request/route/claim/completion state durably holds together across one
  request's whole lifetime, including a real kernel restart mid-scenario,
  and the required retry/crash-recovery/fencing tests are chained into
  that same scenario (`tests/vertical_slice_continuity_contract.rs`, live
  PostgreSQL). Denial and same-route concurrent-claim racing are
  intentionally proven separately, not re-composed into this scenario —
  see Section 7's numbered list for why.
- TLS (nginx sidecars in front of both the kernel's and
  `infernal-inquisitor-simple`'s Kubernetes `Service`s) and ADR-0008
  enrollment, verified end to end against a real kind cluster —
  `infernal-taskmaster-simple` and `infernal-worker-simple` complete real
  signed HTTPS calls, enroll a fresh instance key against the live
  TokenReview API, and poll `GET /v1/routes/eligible` successfully and
  continuously.
- The request-*submitting* half of the vertical slice, as one real signed
  HTTP round trip: a one-off enrolled test identity submitted a real
  signed `POST /v1/requests`, a worker claimed it, stalled past its
  lease, a second worker instance reclaimed and completed it, the first
  worker's stale completion attempt was correctly rejected, and the
  kernel was restarted mid-scenario with no change to the result.
  Postgres showed exactly one request, one route, a two-entry claim
  history, and full audit/decision evidence. This run is also what
  surfaced and closed two further real gaps (the kernel's own outbound
  ADR-0013 evaluator call needed TLS too; `POLICY_EVALUATOR_AUTHORITY`/
  `POLICY_EVALUATOR_ID` were never actually in the tracked kernel
  manifest) and one genuine correctness bug — a completed route was
  reclaimable indefinitely, since fixed in both `WorkClaimRepository`'s
  `claim` and the eligible-route query.

Nothing else belongs on this list. Exclusive delivery, `all_of` selectors,
backlog matching, route transition history, correlation/causation,
artifact content mediation, typed events, generalized search, and any
scheduling policy are real future work, but none of it gates `v0.1.0`.
