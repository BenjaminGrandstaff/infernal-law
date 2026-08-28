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

The minimum kernel requires durable records for identities, authority,
resources and versions, typed relationships, artifacts, decisions, audit,
events, subscriptions, work claims, and idempotency results. Logical and
physical schemas remain design work; their constraints must enforce the
[kernel invariants](minimum-viable-kernel.md), not merely represent the happy
path.

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
