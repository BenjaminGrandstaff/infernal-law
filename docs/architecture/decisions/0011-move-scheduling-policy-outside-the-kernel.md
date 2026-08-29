# ADR-0011: Move scheduling policy to an external scheduler service

- Status: Accepted
- Date: 2026-08-29
- Deciders: Project owner
- Complements: [ADR-0009](0009-use-explicit-subscription-delivery-modes.md), [ADR-0010](0010-use-postgresql-as-the-only-kernel-state-store.md)
- Related: ILK-002, ILK-010, ILK-011, ILK-013

## Context

[ADR-0009](0009-use-explicit-subscription-delivery-modes.md) described "the
scheduler" as an internal kernel step that atomically selects an eligible
incomplete route and creates its assignment/claim, using subscription state,
authorization, readiness, handshake, and capacity together. Read literally,
that step makes the kernel responsible not only for *whether* a route may run,
but for *which* eligible route runs next, *which* worker or node runs it, and
*when* — worker/node preference, priority, affinity, resource-class placement
(for example GPU requirements), backpressure timing, retry timing, and
Kubernetes placement strategy.

Those are operational optimization decisions, not governance decisions. They
change frequently, vary by deployment and workload, and are exactly the kind
of policy the kernel's other requirements deliberately keep out of Rust code
(see the [kernel object boundary](../minimum-viable-kernel.md#kernel-object-boundary)
and [ILK-013](../minimum-viable-kernel.md#ilk-013-mediation)). Folding them
into the kernel would make the kernel a second, competing source of placement
policy in addition to Kubernetes, and every new placement strategy (batch
throughput, GPU affinity, priority lanes) would require a kernel change and
carry kernel-level trust.

## Decision

The kernel and scheduling are split into two roles with one authority
boundary between them:

```text
             KERNEL
          "May it happen?"
               |
               v
        eligible route set
               |
               v
           SCHEDULER
       "When/where should
          it happen?"
               |
               v
         claim request
               |
               v
             KERNEL
        atomic authority
        + ownership check
```

**Kernel-owned (unchanged, non-negotiable):**

- durable requests, routes, and their append-only transition history;
- subscriptions and subscription matching — this determines which services are
  even *authorized possible destinations* for a request, per the kernel's
  existing rule that a source never discovers or selects a destination;
- authorization (ILK-002) and communication admission;
- claim/lease/fencing (ILK-011): atomic acquisition, renewal, expiry recovery,
  current-holder-only completion, and rejection of stale/fenced mutations;
- idempotency (ILK-012) and audit (ILK-008); and
- the atomic state transitions that make all of the above safe under
  concurrency.

**Moved to an external scheduler service:**

- which eligible route runs next (ordering, priority, fairness);
- which worker or node it runs on (affinity, resource-class/GPU requirements,
  Kubernetes placement);
- capacity accounting and backpressure policy;
- retry timing and backoff; and
- any workload-specific placement strategy.

The kernel does not select a worker. It answers a bounded, authenticated query
such as "which incomplete routes are eligible right now for worker class
`cuda.worker.v1`?" — filtered only by what the kernel already owns: active
matching subscription, authorization, admission, and a fresh handshake for
candidate destinations. That is the entire kernel-side "scheduling" logic:
producing a correct eligibility set, never a preferred one.

A scheduler is an ordinary authenticated service principal, not a trusted
kernel extension. It has no direct database access and no elevated contract.
It reads the eligibility query, applies its own policy, and then calls the
same claim contract any other worker would use:

```text
Scheduler
   |
   | claim(route 8, worker B)
   v
Kernel
   |
   |-- still authorized?
   |-- route still eligible?
   |-- already claimed?
   |-- lease valid?
   \-- fencing revision current?
          |
          v
       CLAIMED
```

The kernel remains the final arbiter of every claim regardless of which
scheduler, or how many competing schedulers, requested it. Two schedulers
racing to claim the same route produce exactly one winner under the existing
ILK-011 compare-and-set rules; a scheduler cannot bypass, weaken, or shortcut
those checks.

### The kernel is the scheduler's only source of state

Moving selection policy out of the kernel does not create a second channel
between services. The existing rule that services communicate with the
kernel, not with one another, applies to a scheduler exactly as it applies to
any worker. A scheduler's every input is therefore an authenticated kernel
contract:

- the eligible-route query (candidate work);
- the kernel's relayed health/capacity observation (see the
  [health model](../direct-service-protocol.md#health-model)) — self-reported
  by a worker *to the kernel*, never to a scheduler directly, and merely
  relayed read-only by the kernel; and
- claim, renewal, release, and completion outcomes.

A scheduler MUST NOT receive its scheduling-relevant state from a worker
directly, from a separate event bus or message queue, from Kubernetes objects,
or from a scheduler-local database populated some other way. A scheduler MAY
still consult non-kernel infrastructure for signals the kernel has no reason
to own — node inventory, GPU availability, cluster capacity — but never as a
replacement for kernel-owned request, route, health/capacity relay, or claim
state. This keeps the kernel the single place every scheduler implementation
must trust, and keeps a scheduler swappable without a worker ever needing to
know one exists.

### Reference implementations

The first scheduler ships as its own project, `infernal-taskmaster-simple` —
a FIFO/priority scheduler with no Kubernetes- or GPU-specific logic. It is
built entirely on the kernel's eligibility query and claim contracts, the same
surface any future scheduler uses. Later, more specialized schedulers
(Kubernetes-capacity-aware, GPU-affinity-aware, throughput-batching) are
expected to be separate deployable services rather than kernel modes, for
example `infernal-taskmaster-k8s`, `infernal-taskmaster-gpu`, and
`infernal-taskmaster-batch`. None of them requires kernel code changes or
elevated database privilege; each is validated against the same claim
contract and the same fencing/idempotency invariants.

### Health, readiness, and capacity

Liveness and readiness (`/health/live`, `/health/ready`) remain the process's
own signal to Kubernetes and are unrelated to this decision. Capacity
accounting (`accepting_work`, `max_in_flight`, `current_in_flight`,
`available_slots`, `retry_after`) is a scheduler input, not a kernel gate: the
kernel's eligibility query does not filter on capacity, and the kernel does
not implement backpressure timing. A scheduler that ignores a destination's
reported capacity may still attempt a claim; the kernel's authorization and
fencing checks are unaffected either way.

The worker still submits its signed health/capacity report only to the
kernel, exactly as every other worker-to-kernel interaction works — it is
never sent to a scheduler directly. The kernel stores the latest observation
durably (ADR-0010) and relays it read-only to an authorized scheduler. A
scheduler MAY cache that kernel-sourced data locally as a disposable read
replica for its own efficiency, but MUST NOT source it any other way — not
from the worker directly, not from Kubernetes objects, and not from a
separately populated store. Whatever a scheduler caches remains scheduler-owned
infrastructure, not kernel state, and cannot authorize, assign, or fence work;
it exists only to make the scheduler's already-kernel-sourced read cheaper.

## Consequences

### Positive

- The kernel's job stays governance and correctness: identity, authorization,
  routing, claims, idempotency, and audit. It does not accumulate placement
  policy.
- New scheduling strategies (GPU affinity, batch throughput, priority lanes)
  ship as new deployable services with ordinary service credentials, never as
  kernel changes or elevated trust.
- Multiple schedulers, or none, can coexist safely: the kernel's claim
  arbitration is the single source of truth regardless of who requests a claim.
- `infernal-taskmaster-simple` gives every deployment a working default without
  requiring a bespoke scheduler on day one.

### Negative

- A deployment needs at least one running scheduler service for routed work to
  actually progress; the kernel alone will accept and hold eligible work
  indefinitely without ever assigning it.
- The eligibility query contract (worker-class declaration, pagination,
  freshness) is new kernel-owned surface that must be designed and versioned
  like any other contract.
- Capacity- and priority-aware behavior that used to be implicit in one hub
  process is now split across kernel and scheduler processes, which adds one
  more service to operate and observe.

## Validation

The decision is working when: the kernel can correctly answer "which routes
are eligible for worker class X" without knowing which one will run next; an
external scheduler can claim, lose a race for, or be denied a claim using only
the same contract available to ordinary workers; removing or restarting every
scheduler leaves accepted requests, routes, and claims durable and
un-corrupted with work simply not yet assigned; and two independent scheduler
implementations can be pointed at the same kernel without either requiring
kernel code changes or elevated privilege.
