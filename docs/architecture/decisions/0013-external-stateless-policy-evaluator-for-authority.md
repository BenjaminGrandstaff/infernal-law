# ADR-0013: External stateless policy evaluator for kernel authority

- Status: Accepted
- Date: 2026-08-29
- Deciders: Project owner
- Complements: [ADR-0007](0007-expose-no-sql-command-surface.md), [ADR-0011](0011-move-scheduling-policy-outside-the-kernel.md)
- Related: ILK-001, ILK-002, ILK-004, ILK-007, ILK-012

## Context

ILK-002 Authority is currently unimplemented — a 21-line requirement stub
with no logic. Two of its invariants are in apparent tension:

> The kernel MUST be the final enforcement point and MUST retain the exact
> schema versions, grants, and security context used for its decision.

and the same instinct behind [ADR-0011](0011-move-scheduling-policy-outside-the-kernel.md)
that pulled optimization policy out of the kernel: authorization *policy* —
which combinations of source, action, schema, and scope are actually allowed
— is exactly the kind of business/organizational logic that changes
independently of the kernel and that the kernel's other requirements already
keep out of Rust code (schemas are service-published data, not kernel enum
variants; ADR-0007 forbids a generic expression/query surface inside the
kernel).

The distinction that resolves the tension: **owning the decision** and
**owning the algorithm that produces the decision** are not the same thing.
This project already has a working precedent for that split — communication
admission's actual state-changing logic lives in a PostgreSQL
`security-definer` function, not in the Rust kernel process; the kernel only
reads the resulting flag and gates on it. This ADR takes the same move one
step further: instead of a Postgres function, the evaluator is a separate
authenticated service, and instead of a boolean flag it returns a verdict
over a fact bundle the kernel assembles per decision.

## Decision

**The kernel owns identity, grants, schema registration and activation, fact
assembly, gating, and audit. It owns no authorization policy logic.** A
separate, external, stateless policy evaluator owns only the algorithm that
turns a fact bundle into an allow/deny verdict. It stores nothing of its own;
every fact it evaluates and every grant it references was already durable in
the kernel's PostgreSQL before the call was made.

```text
Kernel                              Policy evaluator
  |                                        |
  | facts: source, action, schema         |
  | version(s), scope/artifact ids,       |
  | grants, destination (if route         |
  | authority), policy bundle ref         |
  |--------------------------------------->|
  |                                        | (stateless: no data of
  |                                        |  its own, only logic)
  |<---------------------------------------|
  | verdict: allow | deny,                |
  | evaluated policy bundle version        |
  |                                        |
  v
kernel records: facts sent, evaluator
identity, policy bundle version,
verdict, timestamp -> ILK-007 decision
record. Gates the mutation on the
verdict. Nothing proceeds without this.
```

Five points settle the design:

### 1. Authenticated channel, no new trust mechanism

The policy evaluator is an ordinary service principal: it enrolls, holds
keys, and signs exactly like every other service under
[ADR-0003](0003-direct-signed-service-rest.md)/ILK-001. The kernel verifies
the evaluator's response against its registered key exactly as it already
verifies any inbound request. The kernel calls the evaluator the same way it
already makes outbound authenticated calls during handshake reconciliation
(ADR-0005) — as the signing party — with one addition beyond what ADR-0005
left open: the evaluator establishes trust in the kernel's current signing
key by fetching [`GET /v1/kernel-identity`](0014-publish-kernel-identity-endpoint.md)
(ADR-0014), rather than relying on undefined static configuration. No other
new trust mechanism is introduced for this security-critical path; it reuses
machinery the kernel already has.

### 2. Fail-closed

An unreachable, erroring, timed-out, or malformed-response policy evaluator
call MUST be treated as denial, never as an implicit allow and never as
"proceed and check later." This is the same posture the kernel already takes
toward PostgreSQL unavailability and disabled communication admission — a
missing answer is not a yes.

### 3. Decision pinning

The verdict, the evaluator's identity, and the policy bundle/version it
claims to have evaluated are recorded and permanently bound to the decision
they produced (an ILK-007 decision record). A later policy change MUST NOT
retroactively alter the meaning of a request already accepted or a route
already materialized under an earlier verdict — that would violate ILK-004's
"never silently overwritten." Route authority, evaluated at a later point in
time than request-acceptance authority for the same request, is a distinct
decision with its own pinned verdict; it is not a re-evaluation of the first.

### 4. One evaluation contract, two call sites

A single generic contract — `evaluate(facts) -> (verdict, policy_bundle_version)`
— is used at both ILK-002 decision points: request-acceptance authority
(facts: source, action, schema versions, scope/artifact identifiers, grants)
and route authority (facts: the same plus the kernel-derived destination and
matching subscription, and destination-scoped grants). The kernel assembles a
different fact bundle at each call site; it does not integrate two separate
evaluator contracts.

### 5. No circularity

The policy evaluator's own reachability depends only on ILK-001 enrollment
and communication admission — neither of which depends on ILK-002 Authority.
There is no bootstrap cycle: the kernel can always determine whether the
evaluator is currently a reachable, admitted service before asking it
anything, using mechanisms that do not themselves require an authority
decision.

## Consequences

### Positive

- Authorization policy — the part of this system most likely to be
  organization-specific and to change on its own schedule — evolves without a
  kernel release, matching the same freedom already given to service-owned
  action and schema vocabularies.
- The kernel stays a thin, uniform gate: no expression/rules engine is added
  to Rust code, preserving ADR-0007's no-code-surface constraint.
- Every decision remains fully reconstructable from the kernel's own audit
  trail (facts, evaluator identity, policy bundle version, verdict) without
  needing to re-run or trust a black box after the fact.
- The same identity/enrollment/signing machinery used everywhere else in the
  kernel is reused; no new trust infrastructure is built for this path.

### Negative

- Every governed mutation now has a synchronous network dependency on the
  policy evaluator being reachable; this adds latency and a new availability
  dependency to the write path, mitigated only by failing closed, not
  eliminated.
- A minimal policy evaluator implementation is now on ILK-002's critical
  path — unlike the scheduler, work simply not progressing is not an option
  here, since nothing can be authorized without an answer.
- Decision pinning requires new durable schema: a facts snapshot, evaluator
  identity, policy bundle version, and verdict per decision, in the same
  shape of work as the request/replay-protection tables already built.
- Grant and schema administration (creation, activation, revocation) still
  need real kernel-side storage and an administrative surface before there is
  anything meaningful for the evaluator to reason about.

## Validation

The decision is working when: no governed mutation proceeds without a
recorded `evaluate()` call and a stored verdict; an unreachable or erroneous
policy evaluator call results in denial, never in silent proceeding; two
otherwise-identical decisions made under different policy bundle versions are
independently reconstructable from the audit trail without ambiguity; a
policy evaluator process holds no state of its own, so restarting it with a
completely fresh process changes nothing about previously recorded decisions;
and a request or route already denied is never retroactively authorized by a
later policy change.
