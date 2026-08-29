# ADR-0009: Use explicit subscription delivery modes and leased route assignments

- Status: Accepted
- Date: 2026-08-29
- Deciders: Project owner
- Complements: [ADR-0003](0003-direct-signed-service-rest.md), [ADR-0006](0006-store-instance-public-keys-in-postgresql.md), [ADR-0007](0007-expose-no-sql-command-surface.md)
- Related: ILK-003, ILK-007, ILK-008, ILK-010, ILK-011, ILK-012
- Refined by: [ADR-0011](0011-move-scheduling-policy-outside-the-kernel.md), which
  moves route *selection* (which eligible route runs next, on which worker)
  to an external scheduler service. The kernel-owned uniqueness, fencing, and
  transition rules below are unchanged; only who chooses among an eligible set
  moves.

## Context

A durable request may match several services. Some request types represent one
piece of work that any compatible service may perform. Other request types must
be delivered independently to every matching destination. Treating both cases
as undifferentiated subscriptions creates duplicate work, ambiguous completion,
and unsafe failover.

Subscriber eligibility may also depend on several state facts being true at
the same time. Concurrent subscription, state, health, assignment, and
completion changes must not let two services complete exclusive work or let a
stale worker mutate a reassigned route.

## Decision

Every request-receiving subscription declares an immutable delivery mode:

- **exclusive** — subscriptions sharing an approved consumer-group key are
  competing consumers. One logical route and one successful completion exist
  for each request/group. The kernel may reassign its leased assignment to a
  different eligible stable service in the same group after failure or expiry.
- **inclusive** — each matching stable destination service receives an
  independent route and completion. Failure of one destination does not move,
  complete, or cancel another destination's route.

The mode, consumer-group key, selector, state predicates, schema versions, and
routing-window policy are fixed when a subscription version is created. They
cannot be changed in place. Disablement and replacement create append-only
history.

### Destination and instance failure

Routes target stable services or exclusive consumer groups, never process
instances. A replacement instance of the same stable service can continue
after the old instance's claim expires and the new instance authenticates,
handshakes, and becomes ready.

For an exclusive route, permanent loss of the assigned stable service does not
create a new request. After the assignment lease expires or is explicitly
released, the kernel appends an expiry/release transition and assigns the same
route to another eligible service in the same consumer group. The new
assignment has a new ID, fencing token, lease, and route revision.

An inclusive route is destination-specific and is not silently transferred to
another stable service. A replacement destination receives its own route while
the request remains inside its declared routing window. Ending the abandoned
route requires an explicit, audited terminal policy decision.

### State predicates

A subscription selector may declare several typed state predicates. The
minimum selector semantics are `all_of`: every predicate must be true for the
subscription to match. Predicates reference approved namespaced state/schema
fields and fixed operators; they cannot contain code, SQL, table names,
procedure names, or caller-defined database expressions. More complex boolean
semantics require a separately versioned selector contract.

The kernel evaluates all predicates from one consistent committed snapshot and
records the selector version plus each state revision used. A state change
causes reevaluation for future routing or assignment. It does not rewrite an
earlier match, assignment, claim, or completion. Revoking active work requires
an explicit fenced transition governed by policy.

### Concurrency and mutation controls

PostgreSQL enforces these logical uniqueness boundaries:

- accepted request: `(source_service_id, request_id)`;
- exclusive route: `(request_id, consumer_group_id)`;
- inclusive route: `(request_id, destination_service_id)`;
- active assignment: at most one per route;
- active work claim: at most one per route; and
- successful completion: at most one per route.

Route materialization, assignment, claim, renewal, release, and completion use
fixed parameterized operations and database transactions. Retried route scans
return the existing route. Assignment and completion are compare-and-set
operations requiring the expected route revision, assignment ID, claim ID, and
fencing token. A stale worker cannot renew, release, or complete work after its
lease has expired or another assignment has been created.

Definitions and transition history are append-only in PostgreSQL. A mutable
PostgreSQL current-state projection may exist for efficient scheduling, but it
is updated in the same transaction as its immutable transition and may always
be reconstructed from history. Database time determines lease expiry. No
process-local projection can authorize, assign, fence, or complete work.

### Wakeup and scheduling

The subscription registry is the interest index, not the work ledger. A
durable cursor or wakeup marker ensures that either request-first or
subscription-first commit order eventually evaluates the same match. The
kernel exposes the resulting eligible-and-incomplete routes through a
durable, authorization-filtered query; it does not itself choose which one
runs next. An external scheduler service (see
[ADR-0011](0011-move-scheduling-policy-outside-the-kernel.md)) selects among
that eligible set and requests an assignment/claim, which the kernel grants
only after re-checking authorization, eligibility, and fencing at claim time.
Health, handshake, capacity, or instance failure pauses or expires assignment;
it never deletes the request, route, or history.

## Consequences

### Positive

- Exclusive work can fail over without request resubmission or duplicate
  completion.
- Inclusive delivery retains independent completion evidence for every
  destination.
- Multiple state requirements have deterministic all-of semantics.
- Fencing and revisions reject stale-worker mutations.
- Request, subscription, route, assignment, claim, and completion histories
  remain auditable.

### Negative

- Route assignment and transition tables add persistence and scheduling
  complexity.
- Consumer-group governance and routing-window retention require explicit
  policy.
- Inclusive subscriptions can create many routes and need bounded backlog
  controls.
- Exactly-once external side effects still require destination idempotency;
  kernel uniqueness guarantees exactly one recorded route completion, not an
  atomic transaction with an external service's database.

## Validation

The decision is working when concurrent exclusive workers produce one route,
one active assignment, and one recorded completion; failure permits a fenced
reassignment without a new request; inclusive subscribers complete independent
routes; all state predicates are evaluated from one recorded snapshot; and a
stale assignment cannot mutate current route state.
