# Data architecture

> Status: Draft  
> Last reviewed: 2026-08-28  
> Owners: TODO

## Database

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
identity table and database constraints for actor kind, lifecycle status, and
display-name validity. Applied migration versions are recorded in
`kernel_schema_migrations`.

The `PostgresIdentityRepository` adapter implements the identity module's
repository contract. Kernel identity behavior remains independently testable
without PostgreSQL, while the opt-in live integration test verifies durable
identity state across new application connections.

The minimum kernel requires durable records for identities, authority,
resources and versions, typed relationships, artifacts, decisions, audit,
events, subscriptions, work claims, and idempotency results. Logical and
physical schemas remain design work; their constraints must enforce the
[kernel invariants](minimum-viable-kernel.md), not merely represent the happy
path.

The planned service credential schema stores public-key fingerprints,
public-key bytes, algorithms, instance and boot IDs, bounded lease revisions
and expiry, activation/revocation state, enrollment provenance, and handshake
results. PostgreSQL is authoritative for this kernel-managed registry, and
registration or renewal occurs only through kernel contracts. Private signing
keys are not database or Kubernetes Secret data: each service process generates
its own key and retains it only for that process lifetime. See
[ADR-0006](decisions/0006-store-instance-public-keys-in-postgresql.md).

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

TODO: Define recovery-point and recovery-time objectives before the database
holds durable data. A local Podman volume is persistent across container
restarts but is not a backup.
