# Kubernetes service authentication

> Status: Superseded by [ADR-0003](decisions/0003-direct-signed-service-rest.md)
> Last reviewed: 2026-08-28
> Owners: TODO

This document preserves the external Kubernetes-authenticator proposal. The
current design is the [direct signed service protocol](direct-service-protocol.md).

## Components and responsibilities

| Component | Responsibility | Database access |
| --- | --- | --- |
| Calling workload | Presents its projected ServiceAccount token and request | None |
| Authenticator | Validates the token, maps the workload, checks admission, and signs an internal assertion | Read-only service registry |
| Registrar/controller | Creates mappings and changes admission through a constrained procedure | Execute admission procedure; no kernel-state writes |
| Kernel | Verifies the authenticator assertion, authorizes, mediates, and audits the operation | Kernel state plus read-only identity lookup |
| User-authentication service | Authenticates humans outside Infernal-Law and calls through its own workload identity | None by default |

The authenticator and registrar MAY be shipped from one codebase, but MUST run
with different Kubernetes ServiceAccounts and database roles. Compromise of the
read-only authenticator must not grant admission-write authority.

## Kubernetes workload credential

Each calling workload uses a dedicated Kubernetes ServiceAccount. Its Pod
receives a short-lived projected token with an audience dedicated to the
Infernal-Law authenticator. Long-lived legacy ServiceAccount token Secrets are
not used.

The authenticator submits the token to the Kubernetes TokenReview API and
checks:

- authentication succeeded;
- the expected audience is present;
- the ServiceAccount namespace and name match a registered mapping;
- bound-object and token validity checks succeeded; and
- the mapped kernel service identity is enabled.

The authenticator's Kubernetes RBAC MUST grant only the API permissions needed
for TokenReview. Calling workloads receive no Infernal-Law administrative RBAC.

## Database admission state

The service registry requires at least:

| Field | Purpose |
| --- | --- |
| `service_id` | Stable kernel identity |
| `cluster_issuer` | Distinguishes Kubernetes trust domains or clusters |
| `namespace` | Namespaced ServiceAccount identity |
| `service_account` | Verified workload name |
| `service_account_uid` | Prevents silent identity reuse after deletion and recreation |
| `enabled` | Admission flag checked on every authentication |
| `created_at`, `updated_at` | Lifecycle evidence |

A boolean flag alone is insufficient for governance history. Every change MUST
also append an immutable admission-history record containing the service ID,
old and new values, administrator identity, reason, correlation ID, and time.

The registrar changes admission only through a database function or stored
procedure that updates the current flag and appends history in one transaction.
Direct table updates by the authenticator, kernel, or normal application role
are prohibited.

## Authenticator-to-kernel assertion

After successful TokenReview and admission lookup, the authenticator issues a
short-lived signed assertion. The signature covers a canonical representation
containing at least:

- assertion version, issuer, audience, issued-at, and expiry;
- stable kernel service ID;
- verified Kubernetes issuer, namespace, ServiceAccount, and UID;
- unique assertion or replay ID;
- request/idempotency ID;
- kernel operation and target; and
- digest of the complete request payload.

The kernel pins the authenticator's public verification key or trusted issuer
configuration. The signing private key is available only to the authenticator.
Plain `X-User`, `X-Service`, or similar headers never establish identity.

## Request flow

1. A workload sends its request and audience-bound ServiceAccount token to the
   authenticator.
2. The authenticator performs TokenReview and maps the verified ServiceAccount
   to a stable service identity.
3. The authenticator reads the current `enabled` flag. Unknown or disabled
   identities are rejected.
4. The authenticator signs a short-lived assertion bound to the request and
   forwards both to the kernel.
5. The kernel verifies the assertion cryptographically, checks freshness and
   replay state, and reconstructs a verified service context.
6. ILK-002 Authority independently decides whether that service may perform the
   operation.
7. The kernel executes through mediation and attributes audit, decisions,
   events, and mutations to the stable service ID.

## Kubernetes isolation

- Only the authenticator may reach the kernel Service port under NetworkPolicy.
- Direct public ingress terminates at the authenticator, not the kernel.
- The registrar uses a distinct ServiceAccount, Deployment or Job, and database
  Secret from the authenticator.
- The kernel, authenticator, registrar, and application workloads each receive
  dedicated ServiceAccounts.
- ServiceAccount tokens are not automatically mounted into Pods that do not
  need Kubernetes API or workload authentication.
- NetworkPolicy is defense in depth; signed-assertion verification remains
  mandatory because policy enforcement depends on the network plugin.

## Failure behavior

- TokenReview unavailable: fail closed; do not mint an assertion.
- Registry unavailable: fail closed; do not use cached enabled state unless a
  separately approved bounded-cache policy exists.
- Unknown or disabled mapping: reject and audit without contacting the kernel.
- Invalid, expired, altered, or replayed assertion: kernel rejects before
  governed state access.
- Authenticator signing-key compromise: rotate the trusted key, revoke the old
  issuer/key, and preserve audit history.

## Acceptance criteria

- A valid token for an enabled mapping produces a kernel-verifiable assertion.
- The wrong audience, namespace, ServiceAccount, UID, or cluster issuer fails.
- Setting `enabled = false` prevents new assertions without deleting identity
  or history.
- A caller cannot bypass the authenticator by reaching the kernel directly or
  forging identity headers.
- Changing the operation, target, request ID, or payload invalidates the
  assertion.
- Replaying an assertion cannot repeat a governed effect.
- The authenticator database role cannot change admission state.
- The registrar database role cannot mutate governed kernel resources.
- A completed operation is traceable to both the stable service identity and
  verified Kubernetes workload identity.

## Implementation sequence

1. Add the service mapping, enabled flag, admission history, and constrained
   registrar procedure in a new migration.
2. Define least-privilege PostgreSQL roles for authenticator, registrar, and
   kernel access.
3. Build TokenReview validation with a required dedicated audience.
4. Define and implement the signed internal assertion format.
5. Add kernel assertion verification, expiry, request binding, and replay
   protection.
6. Deploy dedicated ServiceAccounts, RBAC, Services, Secrets, and NetworkPolicy.
7. Add end-to-end enabled, disabled, bypass, alteration, and replay tests.
