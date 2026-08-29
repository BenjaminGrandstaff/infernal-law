# ADR-0010: Use PostgreSQL as the only kernel state store

- Status: Accepted
- Date: 2026-08-29
- Deciders: Project owner
- Complements: [ADR-0006](0006-store-instance-public-keys-in-postgresql.md), [ADR-0007](0007-expose-no-sql-command-surface.md), [ADR-0009](0009-use-explicit-subscription-delivery-modes.md)
- Related: ILK-003 through ILK-013

## Context

The kernel runs as replaceable Kubernetes processes. Requests, routes,
subscriptions, assignments, work claims, state evaluations, decisions, and
delivery cursors must survive pod failure without relying on a particular
process, node, filesystem, Kubernetes object, or message broker.

Splitting authoritative state between PostgreSQL and local queues, caches, or
external coordination systems would introduce reconciliation races and make it
unclear which copy controls security or work ownership.

## Decision

PostgreSQL is the only durable and authoritative store for kernel-owned state.
Every fact required to recover, authorize, route, schedule, deduplicate, audit,
or resume work is committed to PostgreSQL before the kernel reports success or
makes the effect externally visible.

Kernel processes are disposable. They may retain only ephemeral runtime
material, including:

- active network connections and bounded request/response buffers;
- prepared statements and database connection pools;
- recomputable read caches that never authorize or assign work while stale;
- a process-local health calculation; and
- the instance's private signing key, which is intentionally unrecoverable and
  replaced on every process start.

No ephemeral value is the sole copy of recoverable kernel state. Losing all
kernel processes simultaneously loses no accepted request, route, cursor,
assignment, claim, result, decision, audit record, or registered public state.
New processes reconstruct their work exclusively from PostgreSQL.

### Required PostgreSQL state

PostgreSQL owns at least:

- stable identities, workload bindings, public keys, leases, and handshakes;
- communication admission, authority schemas, grants, and decisions;
- accepted request envelopes, fingerprints, artifacts, and relationships;
- subscription definitions, selector versions, state predicates, cursors, and
  wakeup markers;
- request routes, route revisions, append-only transitions, assignments,
  fencing tokens, and routing windows;
- work claims, renewals, releases, expiries, and completions;
- event/outbox records and durable delivery acknowledgements;
- replay reservations, idempotency results, and correlation bindings; and
- append-only security, administration, routing, and work audit history.

State predicates are evaluated from PostgreSQL revisions in one consistent
transactional snapshot. Lease expiry uses database time. Route selection,
assignment, claim, completion, current-state projection, transition history,
and outbox insertion commit atomically where their invariant requires one
transaction boundary.

### Prohibited authoritative stores

The production kernel does not use process memory, local files, container
filesystems, Kubernetes Secrets or ConfigMaps, local persistent volumes,
in-memory queues, or an external message broker as an authoritative kernel
state store. A future transport or cache may be added only as a disposable
projection over PostgreSQL and cannot acknowledge, authorize, fence, or advance
work independently.

In-memory repository implementations remain permitted in isolated tests. They
are test doubles, never production wiring or a recovery mechanism.

### Failure behavior

When PostgreSQL is unavailable, a kernel process may answer minimal liveness
diagnostics but is not ready. It fails closed for governed reads whose
freshness affects security and for every mutation, request acceptance, replay
reservation, route materialization, assignment, claim, completion, cursor
advance, and delivery acknowledgement. It does not continue from a cache.

Database replication, WAL, backup, restore, and disaster recovery protect the
one state store. A local container volume is persistence for development, not
a production backup strategy.

## Consequences

### Positive

- Any kernel process can fail without losing committed work.
- Security, routing, work ownership, idempotency, and audit share transactional
  consistency and one recovery source.
- There is no cache/queue/database conflict-resolution protocol.
- Horizontal kernel replicas remain operationally disposable.

### Negative

- PostgreSQL availability and performance gate all governed progress.
- Scheduling, wakeup, and outbox workloads must be designed and indexed for
  PostgreSQL.
- Database capacity, replication, backup, and recovery become critical
  operational responsibilities.

## Validation

The decision is working when all kernel pods can be terminated after commits,
fresh pods reconstruct every pending request and route from PostgreSQL, no
duplicate assignment or completion occurs, and database loss of availability
causes fail-closed readiness rather than cache-based progress.
