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

PostgreSQL is the kernel's only authoritative state store. Every kernel process
is ephemeral and replaceable; process memory may contain only disposable or
recomputable runtime material and a deliberately ephemeral instance private
key. No accepted request, route, subscription cursor, assignment, claim,
decision, idempotency result, or audit fact may exist only in memory or on a
kernel filesystem.

The hub uses durable store-and-forward routing. Services communicate with the
kernel, not with one another, and do not discover one another's identities or
runtime instances. A request is accepted and stored even when no eligible
matching subscription exists. The kernel expands one request into zero or more
exclusive-group or inclusive-destination routes as subscriptions match. Each
route remains independently pending until completed or until an explicit
expiry, cancellation, or terminal policy decision is durably recorded.

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
- **Scheduler** — an ordinary, non-privileged service principal that reads the
  kernel's eligible-route query and decides which eligible route runs next and
  on which worker or node. It owns optimization policy (ordering, priority,
  affinity, resource-class placement, capacity, backpressure timing, retry
  timing); it holds no elevated database access and cannot bypass claim
  arbitration. The kernel is its only source of registered request, route,
  health/capacity-relay, and claim state — a scheduler never receives that
  state from a worker directly or from any other event source. See
  [ADR-0011](decisions/0011-move-scheduling-policy-outside-the-kernel.md).
- **Policy evaluator** — an ordinary, non-privileged service principal that
  holds no authorization data of its own. The kernel sends it a fact bundle
  (source, action, schema versions, scope/artifact identifiers, grants, and
  destination when applicable) and it returns an allow/deny verdict plus the
  policy bundle/version it evaluated. The kernel alone owns the grants,
  schemas, and audit trail; an unreachable or erroring evaluator is denial,
  never implicit allow. See
  [ADR-0013](decisions/0013-external-stateless-policy-evaluator-for-authority.md).
- **External user subject** — optional provenance asserted by an authenticated
  service; it is not a kernel principal or credential.
- **Request** — the immutable, signed, durable communication envelope submitted
  by one service. It declares intent and matching metadata but no concrete
  destination service.
- **Request route** — a kernel-owned administrative record binding one request
  to either one exclusive consumer group or one inclusive subscription
  destination. It carries that target's independent routing/work state and
  exposes no destination discovery information to the source service.
- **Exclusive subscription** — a competing-consumer subscription for which one
  request/consumer-group route may be assigned to only one eligible service at
  a time and may be reassigned after a fenced lease expires.
- **Inclusive subscription** — a fan-out subscription for which every matching
  stable destination service owns an independent request route and completion.
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

## Authoritative state boundary

- Every recoverable kernel fact MUST be stored in PostgreSQL before success is
  reported or an externally visible governed effect is released.
- Fresh kernel processes MUST reconstruct all pending work, cursors, leases,
  and decisions exclusively from PostgreSQL.
- Memory caches MUST be disposable and MUST NOT authorize, route, assign,
  claim, complete, acknowledge, or advance work without a current PostgreSQL
  transaction.
- Local files, container filesystems, Kubernetes objects, persistent volumes,
  and message brokers MUST NOT be authoritative kernel state.
- The ephemeral private signing key is intentionally not recoverable state. A
  restarted instance creates a new identity/key pair and registers its public
  record in PostgreSQL before becoming eligible.
- PostgreSQL unavailability MUST make the kernel unready and fail closed for
  governed mutations, security-sensitive reads, request acceptance, replay,
  delivery, and work coordination.
- In-memory repositories MAY exist only as isolated test doubles and MUST NOT
  be used in production wiring.

## Routing ledger

The kernel separates immutable intent, interest, destination progress, and
exclusive ownership:

| Record | Identity and purpose | Multiplicity |
| --- | --- | --- |
| Request | Source-authenticated intent and matching metadata | One accepted record per source/request ID |
| Subscription | A stable service's declared interest and wakeup cursor | Zero or more matches per request |
| Request route | Deduplication and completion boundary for an exclusive group or inclusive destination | At most one per request/group or request/destination |
| Route transition | Append-only evidence of ready, claimed, completed, paused, or terminal progress, including the applicable subscription | Many per route |
| Work claim | Exclusive lease naming the worker currently handling a route | At most one active claim per route; history retained |

An accepted request with no matching subscription is **unrouted**, not failed.
When a subscription matches, the kernel idempotently creates or wakes the
request route for that stable destination. The kernel's next-work query uses
active subscription state and its durable cursor to expose which incomplete
routes are eligible; it does not select which one runs next or on which
worker — that policy belongs to an external scheduler service (see
[ADR-0011](decisions/0011-move-scheduling-policy-outside-the-kernel.md)). The
work-claim contract then atomically arbitrates whichever claim a scheduler
requests: authorized, still eligible, unclaimed, and fencing-current, or
rejected. A completion is scoped to that route and records the subscription
and worker responsible. It does not complete the parent request for any other
destination.

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
- Request-acceptance authority MUST consider the authenticated source,
  namespaced action, artifact type and schema version, permission-policy schema
  version, artifact or scope identifiers, and relevant administrative grants.
- Route authority MUST separately consider the kernel-derived destination,
  matching subscription, and current destination-scoped grants before the
  route is exposed, claimed, or delivered.
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
  schema versions, grants, and security context used for its decision. The
  kernel MAY delegate the allow/deny *algorithm* to an external, stateless
  policy evaluator that stores no data of its own, provided the kernel alone
  owns the grants, schemas, and facts the evaluator is given, and alone
  records the verdict (see
  [ADR-0013](decisions/0013-external-stateless-policy-evaluator-for-authority.md)).
- An unreachable, erroring, or malformed-response policy evaluator MUST be
  treated as denial, never as an implicit allow.
- A recorded authority verdict MUST be pinned to the policy bundle/version
  evaluated at that time; a later policy change MUST NOT retroactively alter
  an earlier accepted request's or materialized route's authorization.
- Request-acceptance authority and route authority are distinct decisions,
  each independently pinned, using one shared evaluation contract with
  different fact bundles rather than two separate integrations.

Acceptance criteria:

- The same request is routed for an authorized source and denied for an
  unauthorized source without reaching the destination or changing governed
  state.
- Registering a schema does not make it active and does not grant its publisher
  permission.
- An active grant applies only to the schema version, action, artifact scope,
  source, optional route destination, and validity period it declares.
- Unknown, inactive, superseded, malformed, or conflicting policy schemas fail
  closed.
- Security-relevant authorization outcomes identify the request, source,
  action, artifact schema, policy schema, applicable grant, and
  administrator-controlled policy revision, plus the route destination and
  subscription when the decision is destination-specific.

Implementation status:

- Complete: the typed domain contract — `Grant`, `Scope`, `PolicyBundleVersion`,
  `PolicyFacts` (shared by both decision points), `Verdict`, and the pinned
  `AuthorityDecision` — plus the `AuthorityRepository` and `PolicyEvaluator`
  trait boundary and `AuthorityService::authorize`, with an independently
  runnable contract test covering default-deny, grant matching and expiry,
  wildcard scope, fail-closed evaluator handling, and that request-acceptance
  and route decisions never share a grant.
- Complete: PostgreSQL-backed, append-only grant storage read through
  `PostgresAuthorityRepository`, and an idempotent, conflict-detecting,
  security-definer `create_authority_grant` administration function that the
  Rust kernel never calls directly — grants are administered out-of-band,
  exactly as communication admission already is.
- Complete: the typed schema domain contract — `SchemaKind` (artifact vs.
  permission-policy, independent namespaces even under the same name),
  `SchemaName`, `ContentDigest`, and the immutable `SchemaVersion` chained to
  its predecessor — plus `SchemaRepository`/`SchemaService::publish`, which
  any authenticated service may call for names it owns to register a new
  version without activating it, and which rejects a different service
  publishing under an already-claimed name
  (`AuthorityError::SchemaNamespaceConflict`). `SchemaStatus` (Published,
  Active, Suspended, Superseded, Retired) exists as a value type read from
  `SchemaRecord`.
- Complete: PostgreSQL-backed schema storage. `publish_authority_schema_version`
  atomically locks the current latest version for a `(kind, name)`, checks
  owner consistency, and assigns the next version and predecessor link; it is
  called directly by `PostgresAuthorityRepository` on behalf of any
  authenticated service, unlike grant creation. `set_authority_schema_status`
  is the administrator-only, idempotent, terminal-state-respecting
  counterpart to `create_authority_grant`, moving a schema through
  Published → Active/Retired → Suspended/Superseded/Retired with append-only
  status audit; superseded and retired are terminal and the Rust kernel never
  calls this function directly.
- Complete: durable decision pinning. `AuthorityService::authorize` mints a
  `DecisionId` and calls a new `AuthorityDecisionRecorder` dependency before
  ever returning a decision; recording failure fails `authorize` itself
  rather than returning an unrecorded decision, the same fail-closed posture
  used everywhere else in the kernel. `PostgresAuthorityRepository`
  implements the recorder with a plain append-only insert into
  `authority_decisions` — kernel bookkeeping, not administration, so there is
  no out-of-band function gating it, unlike grants and schema status.
- Complete: schema version references are mandatory on `PolicyFacts` and
  `Grant`, not optional. `SchemaVersionRefs` bundles one artifact schema
  version and one permission-policy schema version; `Grant::permits` requires
  an exact match on both, so reactivating, retiring, or superseding a schema
  version never silently extends or breaks a grant pinned to a specific
  version. PostgreSQL enforces the same requirement structurally: both
  `authority_grants` and `authority_decisions` carry mandatory,
  foreign-key-checked columns for both schema versions, and
  `create_authority_grant` additionally checks that each referenced version
  is the expected kind (artifact vs. permission-policy) before accepting a
  grant.
- Complete: the `GET /v1/kernel-identity` route publishing this process's
  current public signing key, unauthenticated by design, so a future caller
  (the policy evaluator, or the handshake reconciler's outbound transport)
  can verify a kernel-signed message without static configuration that
  breaks on every kernel restart (ADR-0014). Correct behavior behind multiple
  kernel replicas remains a documented follow-up.
- The outbound signed-call machinery itself now exists outside the kernel:
  `infernal-client-rs` ([ADR-0012](decisions/0012-rust-first-client-sdk-family-over-signed-rest.md))
  implements the signing side of ADR-0003 and verifying a kernel identity
  against `GET /v1/kernel-identity`, and this repository's own test suite
  proves a request it signs is accepted by the kernel's real, unmodified
  `ServiceRequestVerifier`, and — the mechanism a reference policy evaluator
  will actually run — that a request the kernel signs with its own
  `InstanceCredential` via `sign_with` is correctly accepted by
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
  exists to actually call — it verifies the kernel's signed request against
  the kernel's self-published identity using `infernal-client-rs`'s own
  `verify_incoming`, then applies the same "allow if a grant matched" shape
  of policy `HttpPolicyEvaluator` expects a verdict for. Its own test suite
  proves this against a live (if fake) kernel-identity HTTP server, not just
  in-process values.
- Complete: `Application::authority_service` builds an `HttpPolicyEvaluator`-backed
  `AuthorityService` on demand (env-configured `POLICY_EVALUATOR_AUTHORITY`/
  `POLICY_EVALUATOR_ID`), and ILK-010's `POST /v1/subscriptions` and
  `DELETE /v1/subscriptions/{id}` handlers call it before mutating —
  `GET /v1/subscriptions` does not, since listing the caller's own data does
  not itself change governed administrative state. An unconfigured or
  unreachable evaluator, or a deny verdict, fails closed (`503`/`403`),
  never an implicit allow. Subscription management has no artifact content
  to authorize, so these calls use the reserved
  `NO_ARTIFACT_SCHEMA_VERSION`/`NO_ARTIFACT_PERMISSION_POLICY_SCHEMA_VERSION`
  pair (`src/kernel/authority.rs`) rather than a fabricated one-off schema
  version.
- Complete: `POST /v1/authority/schemas` exposes `SchemaService::publish`
  over the governed HTTP boundary (`src/http/schema_dto.rs`) — any
  authenticated caller may publish a schema version under its own verified
  identity for a name it owns; a different service already owning that
  `(kind, name)` is rejected as a sanitized `409`. Publishing alone never
  activates a schema or grants its publisher permission (ILK-002's own
  wording), so this route requires no ILK-002 authority decision, only
  authentication.
- Correction to an earlier revision of this section: it claimed nothing
  links an enrolled instance's signing `service_id` to an `identities` row.
  That was wrong — `service_instances.service_id` (every enrolled
  instance) and `service_enrollment_bindings.service_id` are both `NOT
  NULL` foreign keys into `identities` already, so enrollment itself is
  impossible under a `service_id` lacking an `identities` row. There is no
  remaining code gap here.
- Pending, for a real (non-`503`, non-default-deny) authority decision in
  production: out-of-band provisioning — an `identities` row and
  enrollment binding for each calling service, an `identities` row for
  whatever `POLICY_EVALUATOR_ID` names, and at least one grant under
  `NO_ARTIFACT_SCHEMA_VERSION`/`NO_ARTIFACT_PERMISSION_POLICY_SCHEMA_VERSION`
  for an action to actually be allowed — the same administrative pattern
  grants and schema status already use, not new code.
  `tests/postgres_authority_repository.rs`'s ignored integration tests
  already exercise the identity-then-schema-then-decision path end to end
  against a real Postgres backend. Also pending: administrator-driven
  schema activation (`set_authority_schema_status` is Postgres-only, not
  yet exposed administratively) for whatever schema versions real
  artifact-bearing grants end up referencing (ADR-0013).
- The existing signature, replay, and communication-admission gate is the
  required precondition and MUST remain ahead of this authority step.

### ILK-003: Requests

Invariants:

- Every request MUST have a stable ID unique within its source identity's
  namespace and MUST be permanently bound to one semantic request fingerprint.
- A request ID MUST NOT be reassigned to different content, action, artifact
  schema, permission schema, or routing intent.
- The authenticated request envelope and content digest MUST become durable
  before the kernel reports acceptance.
- A request MUST identify its source, namespaced action, artifact descriptor,
  permission-policy schema reference, correlation metadata, and creation time.
- A request MUST NOT name or expose a concrete destination service. The kernel
  derives destination routes only from authorized matching subscriptions.
- Request acceptance and durable storage MUST NOT depend on a matching active
  subscription, reachable destination instance, current health, or available
  delivery capacity.
- A request without an eligible matching subscriber MUST remain durably
  unrouted; it MUST NOT be rejected or silently discarded merely because no
  subscriber exists yet.
- A matching subscription MUST materialize at most one exclusive route for the
  request/consumer group or one inclusive route for the request/stable
  destination. Those unique keys MUST make repeated scans, retries, and
  subscription wakeups idempotent.
- One request MAY have routes to many destination services. Every route MUST
  have its own state and append-only transition history.
- Completing one route MUST record the subscription and destination for which
  it completed and MUST NOT complete, cancel, or advance another route.
- The current worker MUST be represented by the route's active work claim;
  completed and expired claims MUST remain available to show who worked or
  attempted the route.
- A source MUST NOT receive destination discovery information. The kernel owns
  subscriber discovery, instance selection, handshake, and delivery.
- Request acceptance MUST NOT imply authorization, delivery, work completion,
  or acceptance of the artifact by the destination service.
- Business-domain objects MUST remain service-owned artifacts rather than
  becoming generic kernel resource types.

Acceptance criteria:

- A successfully accepted request remains addressable after process restart.
- Retrying the same semantic request under the same request ID does not create
  another request.
- Reusing a request ID with a different action, schema reference, artifact
  digest, or payload is rejected deterministically.
- The kernel can route a previously accepted request without interpreting its
  service-specific artifact content.
- A request accepted before its matching subscription exists becomes eligible
  for delivery after that subscription is committed, without source resubmission.
- A subscription-creation race cannot lose a matching pending request or create
  more than one accepted request record.
- Two matching destination services produce two independently tracked routes;
  completing either route leaves the other route eligible for work.
- Replaying backlog scans or wakeups cannot create duplicate work for an
  existing exclusive-group or inclusive-destination route.

Implementation status:

- Complete: the typed immutable core records a stable Request ID, source
  service, and validated namespaced action without a concrete destination.
- Complete: the core contract has an independently runnable test and exposes
  no field mutation operations.
- Complete: the artifact descriptor and permission-policy schema reference
  this invariant list requires. `Request` carries `scope`/`schema_versions`
  using the same `authority::Scope`/`SchemaVersionRefs` types ILK-002
  evaluates against (`PolicyFacts::for_request_acceptance`), so there is one
  validated representation of each, not a parallel one that could drift.
  `Request::fingerprint()` deterministically hashes all four immutable
  fields (source, action, scope, schema versions), length-prefixed so no
  combination of values can collide by concatenation.
- Complete: atomic PostgreSQL acceptance scoped to `(source_service_id,
  request_id)`, safe-retry classification, conflict rejection on rebinding,
  and append-only acceptance audit surviving process restart. Both schema
  version columns are mandatory, foreign-keyed to `authority_schema_versions`,
  and a foreign-key violation there is now reported as
  `RequestError::UnknownSchemaVersion` (matched by Postgres constraint name),
  distinct from `UnknownSource` -- conflating the two would misreport a
  valid caller as unauthenticated.
- Complete: authenticated-envelope construction. `POST /v1/requests`
  (`src/http/request_dto.rs`) builds the request from the caller's own
  verified identity and, notably, the *signed envelope's own*
  `infernal-request-id` (`VerifiedServiceRequest::request_id`) as the
  durable ILK-003 request ID -- not a body field, and not freshly minted
  per call. The caller already controls that value and retries a lost
  response with it unchanged, so reusing it is what makes submission
  idempotent under retry without a second, redundant identifier. Submission
  is authorized by a real ILK-002 decision built from the request's own
  action, scope, and schema versions -- the artifact-bearing case that
  machinery exists for, unlike ILK-010 subscription management's
  `NO_ARTIFACT_SCHEMA_VERSION` sentinel. `GET /v1/requests/{id}` reads back
  only the caller's own accepted request; another service's request looks
  identical to one that does not exist.
- Pending: correlation relationships, exclusive-group and
  inclusive-destination route records and transition history, and
  subscription-triggered backlog routing.

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
  An authority decision produced by an external policy evaluator additionally
  records that evaluator's identity and the policy bundle/version it claimed
  to evaluate (ADR-0013).
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
  service, instance and key, namespaced action, artifact and permission schema
  versions, administrative revision, time, outcome, and correlation ID. Route
  records additionally include destination service and subscription.
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
- A request-receiving subscription MUST declare `exclusive` or `inclusive`
  delivery semantics; an omitted or unknown mode MUST fail closed.
- An exclusive subscription MUST declare an approved consumer-group identity.
  All services in that group compete for one request/group route and one
  completion; failover reassigns that route rather than resubmitting the request.
- An inclusive subscription MUST create an independent route for every matching
  stable destination service within the request's routing window.
- A subscription MAY require multiple typed state predicates. The minimum
  semantics MUST be `all_of`, evaluated from one consistent committed snapshot;
  every predicate must be true before a route becomes eligible.
- Subscription modes, group identities, selectors, predicate sets, referenced
  schema versions, and routing-window policies MUST be immutable after creation.
  Replacement creates a new version and preserves the old definition.
- Selector predicates MUST be declarative approved fields and fixed operators;
  caller-supplied SQL, code, database identifiers, and executable expressions
  are forbidden.
- Committing a subscription MUST make pre-existing matching pending requests
  eligible for routing; subscription timing MUST NOT determine whether a
  request is retained.
- The subscription registry supplies eligible destination services and wakeup
  cursors; it MUST NOT be overwritten with route progress or work history.
- The kernel MUST use a durable subscription cursor or equivalent wakeup marker
  to find both new and pre-existing matching requests without loss.
- Subscription changes MUST be authorized and audited.
- Pausing or deferring delivery for readiness, health, or capacity reasons is
  scheduler policy (ADR-0011) and MUST NOT delete or disable durable
  subscription state.
- Every kernel instance MUST continuously discover reachable instances for
  active subscriptions and complete a fresh, mutual proof-of-possession
  handshake before delivering to an instance.

Acceptance criteria:

- A service receives or can retrieve only requests or events matching its
  active subscriptions, destination, approved schemas, and authorization scope.
- With no matching subscription, an accepted request remains durably pending.
  Creating an eligible matching subscription later exposes that backlog to the
  subscriber without requiring the source to retry or know the subscriber's
  runtime identity.
- The kernel's eligibility query returns incomplete routes filtered by active
  subscription, authorization, and handshake state, excluding completed routes
  and routes protected by an active work claim. An external scheduler service
  selects which eligible route to claim next and for which worker; readiness
  and capacity are scheduler policy inputs, not kernel filters (see
  [ADR-0011](decisions/0011-move-scheduling-policy-outside-the-kernel.md)).
- If an exclusive destination instance or service fails, its assignment lease
  expires and the same route can be fenced and reassigned to another eligible
  service in the consumer group. No new request is created.
- A stale worker cannot renew, release, or complete a reassigned route because
  every mutation requires the current route revision, assignment ID, claim ID,
  and fencing token.
- Concurrent evaluation produces at most one exclusive request/group route or
  one inclusive request/destination route. Exactly one active assignment, one
  active claim, and one successful completion may exist per route.
- The selector version and state revisions used for each eligibility decision
  remain queryable; later state mutations do not rewrite prior decisions.
- Disabling a subscription prevents new deliveries without deleting its
  history.
- A scheduler deferring claims for saturation, stale health, or lack of
  capacity does not advance or lose the durable cursor; resumed claiming picks
  up from the same eligible set (ADR-0011).
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
- Complete: signed REST operations for the subscription lifecycle —
  `POST /v1/subscriptions` (create), `GET /v1/subscriptions` (history, or
  active-only via `?active=true`), and `DELETE /v1/subscriptions/{id}`
  (disable) — dispatched from `src/http.rs` only after the existing
  signature/replay/admission gate admits the request. The caller's own
  verified identity (`VerifiedServiceRequest::service_id`), never a
  request-body field, is what the domain layer uses as the owning service,
  so a caller can only ever create, list, or disable its own subscriptions;
  disabling another service's subscription is indistinguishable from
  disabling one that does not exist. These routes no longer return `501`.
- Complete: create and disable additionally require an ILK-002 authority
  decision (see ILK-002's own status above for the evaluator wiring and the
  still-open gaps that keep it fail-closed against a real Postgres backend
  today); list does not, since it changes no governed administrative state.
- Pending: typed delivery modes, consumer groups, immutable all-of state
  selectors, pending request backlog matching, fenced route assignment and
  completion, delivery cursors, production outbound handshake transport, and
  the eligible-route query contract external scheduler services will use
  (ADR-0011).
- Out of kernel scope: capacity-aware delivery, worker/node placement, and
  retry-timing policy. Those belong to an external scheduler service, not the
  kernel (ADR-0011).

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
- A claim MUST be bound to the route revision, assignment ID, worker service and
  instance, lease, and monotonically increasing fencing token.
- Route reassignment MUST occur only after atomic release, expiry, or an
  authorized revocation transition. Liveness observations alone MUST NOT
  silently transfer ownership.

Acceptance criteria:

- Concurrent claim attempts produce exactly one active holder.
- Another worker can claim work after the prior claim expires.
- A stale holder cannot complete work after losing its claim.
- Concurrent failover and completion produce one winner: either the current
  holder completes, or reassignment advances the fence and makes that holder
  stale.

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
- idempotency retention period;
- request payload/reference thresholds and storage-proxy limits; and
- the eligible-route query contract's worker-class declaration, pagination,
  and freshness semantics for external scheduler services (ADR-0011).

Each consequential choice should be recorded as an ADR and linked back to the
affected `ILK-*` requirements.
