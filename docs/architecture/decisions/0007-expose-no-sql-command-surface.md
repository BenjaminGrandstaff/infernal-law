# ADR-0007: Expose no SQL command surface

- Status: Accepted
- Date: 2026-08-28
- Deciders: Project owner
- Complements: [ADR-0006](0006-store-instance-public-keys-in-postgresql.md)
- Related: ILK-002, ILK-008, ILK-012, ILK-013

## Context

PostgreSQL is the kernel's system of record, but callers must not gain a
database command channel through the kernel. Accepting SQL, query fragments,
table names, stored-procedure names, or similar database instructions would
bypass typed contracts and make authority, validation, idempotency, audit, and
versioning difficult to enforce consistently.

The kernel still needs internal SQL to implement its persistence adapters and
schema migrations. That SQL is trusted application code, not caller input.

## Decision drivers

- Preserve the kernel as the sole mediation boundary.
- Prevent direct or indirect database mutation by services and workers.
- Keep authorization at the operation and resource level rather than the SQL
  statement level.
- Make every supported action explicit, testable, versioned, and auditable.
- Prevent SQL injection and stored-procedure passthrough designs.

## Decision

Infernal-Law exposes no operation that accepts or executes caller-supplied SQL.
This prohibition applies to services, workers, administrators, subscriptions,
artifacts, events, and every public or internal network API.

The kernel MUST NOT accept:

- raw SQL statements or batches;
- SQL expressions, predicates, joins, ordering, or pagination fragments;
- caller-selected table, column, schema, function, or procedure names;
- a generic query or database-console operation; or
- encoded SQL intended for later execution from an artifact, event, or job.

Callers use typed, versioned kernel contracts. Kernel-owned infrastructure
adapters translate those operations into fixed or internally allowlisted,
parameterized statements. Values are bound as parameters rather than
interpolated into SQL. Schema identifiers and statement structure are selected
only by trusted code.

Idempotent migrations bundled with the application are permitted because they
are reviewed deployment artifacts and are not supplied through a kernel
contract. Emergency database administration is an out-of-band operational
procedure with separate credentials and audit controls; it is not a kernel
command and must not be exposed to normal workloads.

SQL text may be stored as inert evidence when an application-specific resource
requires it, but the kernel MUST treat it as data and MUST NOT execute it.

## Consequences

### Positive

- Callers cannot bypass mediation with a database statement.
- Authority and audit remain expressed in stable domain operations.
- Persistence can change without changing the public contract.
- Injection risk is reduced by prohibiting caller-controlled statement
  structure and requiring parameter binding.

### Negative

- Every supported query or mutation requires an explicit kernel contract.
- Flexible search needs a constrained domain query model rather than SQL.
- Operational database repair requires a separate controlled procedure.

### Follow-up work

- Add typed contracts for public-key registration and lease renewal.
- Keep database connections and repository methods private to infrastructure.
- Add tests proving unknown or SQL-shaped operations are rejected before any
  repository call.
- Define the out-of-band database administration and audit procedure before
  production use.

## Validation

The decision is working when no API schema contains a SQL field or generic
query operation; normal workload credentials contain no database credential;
all repository statements have kernel-owned structure and bound values; and a
SQL-shaped request is rejected before a database adapter is invoked.
