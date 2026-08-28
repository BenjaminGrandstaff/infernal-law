# System overview

> Status: Draft  
> Last reviewed: 2026-08-28  
> Owners: TODO

## Purpose

**Infernal-Law** is a governance kernel that mediates work performed by human,
service, and worker identities. It provides durable, versioned resources and
evidence while making authority, decisions, audit history, events, and work
coordination explicit and traceable.

## Scope

### In scope

- Identity-aware and authorized kernel operations
- Durable, versioned resources, relationships, artifacts, and decisions
- Append-only audit history and committed-change events
- Worker subscriptions, exclusive work claims, and idempotent requests
- A mediation boundary that prevents workers from directly mutating kernel
  state

### Out of scope

- Direct worker access to kernel-owned persistence
- Silently destructive updates to accepted history
- Application-specific worker behavior beyond kernel coordination contracts
- Capabilities beyond the documented [minimum viable kernel](minimum-viable-kernel.md)
  until they are separately specified

## System context

TODO: List the people and external systems that interact with infernal-law.
Replace this placeholder with a context diagram once those relationships are
known.

| Actor or system | Relationship | Data exchanged |
| --- | --- | --- |
| Human or service actor | Requests governed operations | Identity evidence, commands, query results |
| Worker | Subscribes, claims work, and submits artifacts | Events, claims, evidence, results |
| Identity provider | Supplies verifiable identity evidence | Credentials and identity attributes |
| Event consumer or transport | Delivers committed facts to workers | Typed, versioned events |

## Major components

| Component | Responsibility | Technology | Source |
| --- | --- | --- | --- |
| HTTP service | Exposes the application and health endpoints | Rust | `src/` |
| Container image | Packages the service as a non-root process | Podman/OCI | `Containerfile` |
| Database | Stores relational and vector data | PostgreSQL 17 with pgvector | `containers/postgres/` |
| Runtime deployment | Runs and exposes the service | Kubernetes | `k8s/base/` |

## Key flows

### Governed mutation

1. An identified actor submits an idempotent operation through a kernel
   contract.
2. The kernel authenticates the actor, checks authority, and validates the
   operation against current versioned state.
3. The kernel atomically stores the state change, audit record, promised event,
   and idempotent result.
4. After commit, subscribed workers can receive or retrieve the typed event and
   safely claim associated work.

## Data

PostgreSQL is the planned system of record and pgvector provides vector-column
and similarity-search support. The application schema, data ownership,
retention, and sensitivity classification remain to be defined. See the
[data architecture](data.md).

## Quality goals

Rank the few qualities that drive architectural tradeoffs.

| Priority | Quality | Concrete scenario or target |
| ---: | --- | --- |
| 1 | Integrity | No caller can bypass authority, versioning, or mediation rules to mutate governed state. |
| 2 | Traceability | A governed outcome can be reconstructed from identities, versions, decisions, artifacts, and audit records. |
| 3 | Retry and concurrency safety | Duplicate requests and competing workers cannot create duplicate effects or simultaneous active claims. |

## Constraints

- The project is distributed under the MIT License.
- The project is classified as EAR99 for U.S. export-control purposes. See the
  [export-control notice](../export-control.md).
- All minimum kernel behavior must satisfy the invariants in the
  [minimum viable kernel specification](minimum-viable-kernel.md).
- TODO: Other legal, organizational, technical, cost, or delivery constraint

## Risks and open questions

| Item | Impact | Owner | Next step |
| --- | --- | --- | --- |
| TODO | TODO | TODO | TODO |

## Related decisions

- No ADRs recorded yet.
