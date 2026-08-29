# Architecture Decision Records

Architecture Decision Records (ADRs) capture choices that materially affect
the system's structure, quality attributes, dependencies, or operating model.
They preserve the context and tradeoffs behind a decision.

## Creating an ADR

1. Copy [`template.md`](template.md).
2. Name it with the next sequence number and a short kebab-case title, for
   example `0001-use-postgresql.md`.
3. Set its status to `Proposed` while it is under discussion.
4. Change the status to `Accepted` when the decision is made.
5. Link superseding and superseded ADRs rather than rewriting history.

## Status values

- **Proposed** — under consideration
- **Accepted** — approved and active
- **Deprecated** — retained but discouraged
- **Superseded** — replaced by another ADR
- **Rejected** — considered but not selected

## Decision index

| ADR | Status | Date |
| --- | --- | --- |
| [ADR-0001: Separate user and service authentication](0001-separate-user-and-service-authentication.md) | Superseded | 2026-08-28 |
| [ADR-0002: Use an external Kubernetes service authenticator](0002-external-kubernetes-authenticator.md) | Superseded | 2026-08-28 |
| [ADR-0003: Use direct signed REST communication](0003-direct-signed-service-rest.md) | Accepted | 2026-08-28 |
| [ADR-0004: Provision service keys with Kubernetes Secrets](0004-provision-service-keys-with-kubernetes-secrets.md) | Superseded | 2026-08-28 |
| [ADR-0005: Use ephemeral per-instance service keys](0005-use-ephemeral-per-instance-service-keys.md) | Accepted | 2026-08-28 |
