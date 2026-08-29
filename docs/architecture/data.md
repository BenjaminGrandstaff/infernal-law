# Data architecture

> Status: Draft  
> Last reviewed: 2026-08-29
> Owners: TODO

## Database

PostgreSQL is the only durable and authoritative store for kernel-owned state.
Kernel processes, containers, and pods are disposable. They do not own a local
queue, journal, cursor, claim ledger, or recovery file. Every recoverable fact
and every transition needed after restart must already be committed in
PostgreSQL. See
[ADR-0010](decisions/0010-use-postgresql-as-the-only-kernel-state-store.md).

Local development uses PostgreSQL 17 with the pgvector extension. The
project-specific image is defined in `containers/postgres/Containerfile`, and
the extension is enabled during first-time database initialization.

Database files live in the Podman-managed `infernal-law-postgres-data` volume.
The host exposes PostgreSQL only on the loopback interface at port 5432.

The Rust process connects through the pooled `Database` adapter in
`src/infrastructure/database.rs`. Startup verifies both PostgreSQL connectivity
and the presence of pgvector. The adapter owns raw database access so kernel
capability modules do not depend directly on the PostgreSQL client library.
Connection URLs are treated as secrets and the configuration type does not
implement debug formatting, preventing accidental password disclosure through
routine diagnostics.

The initial adapter uses an unencrypted PostgreSQL connection for local and
private-network development. TLS configuration is required before connecting
to a database over an untrusted network.

PostgreSQL is an internal implementation detail, not a kernel command surface.
Only infrastructure adapters and trusted migrations contain SQL. Callers
submit typed domain operations; they cannot submit statements, expressions,
identifiers, or procedure names for execution. Adapter statements bind caller
values as parameters and keep statement structure under kernel control. See
[ADR-0007](decisions/0007-expose-no-sql-command-surface.md).

## Schema migrations

Idempotent SQL migrations live in `migrations/` and are applied by the
application wiring before the HTTP listener starts. Migration 0001 creates the
identity table and its constraints. Migration 0002 creates service-instance,
immutable public-key, bounded lease, and append-only registry-audit storage.
Migration 0003 creates disabled-by-default Kubernetes workload bindings and
hashed, expiring, single-use initial-enrollment challenges.
Migration 0004 creates stable-service subscriptions, one-active-event
uniqueness, immutable disabled history, and append-only subscription audit.
Migration 0005 creates append-preserving per-kernel handshake challenges,
successful handshake history, freshness indexes, and handshake audit records.
Migration 0006 creates immutable service/request-ID fingerprint bindings,
key-scoped nonce-digest reservations, and append-only replay outcome audit.
Migration 0007 creates default-deny communication admission, automatic
one-to-one records for every stable service identity, idempotent administrative
changes, and append-only admission history.
Migration 0008 creates append-only accepted requests scoped to
`(source_service_id, request_id)`, a semantic fingerprint binding that rejects
rebinding to different content, and append-only acceptance audit.
Migration 0009 creates append-only ILK-002 authority grants, an idempotent
conflict-detecting `create_authority_grant` administration function, and
append-only grant administration audit; the Rust kernel only ever reads
grants, exactly as it only ever reads communication admission.
Migration 0010 creates ILK-002 schema versions with an atomic,
namespace-conflict-detecting `publish_authority_schema_version` function that
the Rust kernel calls on behalf of any authenticated service publishing a
schema it owns, plus an idempotent, terminal-state-respecting
`set_authority_schema_status` administration function and append-only status
audit for activation/suspension/supersession/retirement, which stay
administrator-only exactly like grant creation.
Migration 0011 creates append-only ILK-002 authority decisions: every
`AuthorityService::authorize` call durably records its facts, verdict,
evaluator identity, and policy bundle/version (absent only when the
evaluator could not be reached) before the decision is ever returned to a
caller. This is ordinary kernel bookkeeping written directly by the kernel
role, not administration, so unlike grants and schema status there is no
out-of-band function gating it.
Migrations 0012 and 0013 make an artifact schema version and a
permission-policy schema version mandatory, foreign-key-checked fields on
every authority grant and every authority decision respectively — a grant or
a decision citing no schema version, or the wrong kind of schema version in
either slot, is now a database-level impossibility rather than merely a
convention. `create_authority_grant`'s signature and its idempotent
correlation-ID conflict check both grew to cover the two new fields; the
already-strict foreign keys mean these migrations only apply cleanly to a
database with no pre-existing rows in these tables, which matches this
project's stage.
Applied migration versions are recorded in `kernel_schema_migrations`.

The `PostgresIdentityRepository` adapter implements the identity module's
repository contract. Kernel identity behavior remains independently testable
without PostgreSQL, while the opt-in live integration test verifies durable
identity state across new application connections.

The minimum kernel requires PostgreSQL records for identities, authority,
requests and versions, typed relationships, artifacts, decisions, audit,
events/outbox delivery, subscriptions and wakeup cursors, routes and
assignments, work claims, replay, and idempotency results. Logical and physical
schemas for the remaining capabilities are design work; their constraints must
enforce the [kernel invariants](minimum-viable-kernel.md), not merely represent
the happy path.

The service credential schema stores public-key fingerprints,
public-key bytes, algorithms, instance and boot IDs, bounded lease revisions
and expiry, activation/revocation state, enrollment provenance, and handshake
results. PostgreSQL is authoritative for this kernel-managed registry. The
repository, initial Kubernetes TokenReview enrollment contract, application
wiring, and bounded JSON enrollment submission route are implemented; outbound
challenge delivery and renewal authentication remain pending. Private signing
keys are not database or Kubernetes Secret data: each service process generates
its own key and retains it only for that process lifetime. See
[ADR-0006](decisions/0006-store-instance-public-keys-in-postgresql.md).
Initial enrollment is defined by
[ADR-0008](decisions/0008-use-kubernetes-tokenreview-for-initial-enrollment.md).

Replay protection stores SHA-256 nonce digests rather than raw nonces. Nonce
uniqueness is scoped to the ephemeral key. Stable request IDs are scoped to the
service and permanently bound to a semantic request fingerprint. A newly
signed request with the same ID and fingerprint is classified as a safe retry
for ILK-012; a repeated nonce is rejected as wire replay, and the same request
ID with different content is rejected as a conflict. Fresh, safe-retry, replay,
and conflict outcomes are appended to protected audit history.

Accepted requests are durable and append-only: PostgreSQL uniquely keys each
request on `(source_service_id, request_id)`, retrying the same request under
the same fingerprint returns the original record, and rebinding a request ID
to a different action or fingerprint is rejected rather than overwritten.
Triggers reject in-place mutation or deletion of accepted requests and their
acceptance audit history. See
[ADR-0009](decisions/0009-use-explicit-subscription-delivery-modes.md).

Communication admission is separate from identity lifecycle, credentials,
health, and subscriptions. The Rust kernel has a fixed read-only repository
contract and cannot toggle admission. PostgreSQL exposes one fixed,
transactional `set_service_communication_admission` administration function;
`PUBLIC` cannot execute it, direct row updates are trigger-rejected, and every
new correlation ID appends old/new state, administrator identity, reason,
revision, outcome, and commit time. Production deployment must grant function
execution only to a distinct administration database role and use a separate
non-owner runtime role for the kernel.

## Vector storage

The `vector` extension is installed, but the application does not yet define an
embedding table. Choose and document the following before adding one:

- embedding model and vector dimensions
- distance function (`cosine`, inner product, or Euclidean)
- index type and tuning parameters
- source-record ownership and deletion behavior
- metadata schema and tenant isolation

Changing embedding dimensions or models generally requires a migration or a
parallel column/table, so that choice should be captured in an ADR.

## Credentials

Local credentials are read from the ignored
`containers/postgres/postgres.env` file. The checked-in example contains no
usable secret. Production credentials must come from the deployment platform's
secret-management facility rather than from source-controlled manifests.

## Backup and recovery

All kernel recovery originates from PostgreSQL, so production recovery-point
and recovery-time objectives, WAL retention, replication, restore rehearsal,
and backup verification are required before production use. A local Podman
volume is persistent across container restarts but is not a backup.
