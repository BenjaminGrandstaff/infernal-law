# ADR-0004: Provision service keys with Kubernetes Secrets

- Status: Superseded
- Date: 2026-08-28
- Deciders: Project owner
- Complements: [ADR-0003](0003-direct-signed-service-rest.md)
- Superseded by: [ADR-0005](0005-use-ephemeral-per-instance-service-keys.md)
- Related: ILK-001, ILK-008, ILK-012, ILK-013

## Context

Direct signed REST communication requires every service to have an asymmetric
keypair. The private key must be available to the service workload without
being committed to source control or exposed to the kernel. The kernel needs a
durable public key to verify requests even when the Kubernetes API is
unavailable.

Creating a service spans PostgreSQL and Kubernetes, which do not share a
transaction. Provisioning must therefore tolerate retries and partial failure
without accidentally admitting a service that lacks a complete, matching key
registration.

## Decision drivers

- Generate credentials as part of service creation rather than by hand.
- Keep private signing keys out of PostgreSQL, images, logs, and Git.
- Let the kernel verify requests without permission to read Kubernetes Secrets.
- Default new services to unable to communicate.
- Make provisioning and rotation idempotent and recoverable.
- Limit Secret access to the service that owns the key.

## Considered options

1. Let each workload generate and self-register its key at first startup.
2. Have a narrowly privileged service provisioner generate the keypair, store
   it in a Kubernetes Secret, and register the public half with the kernel.
3. Store the keypair only in Kubernetes and let the kernel read Secrets during
   request verification.

## Decision

Infernal-Law will use option 2.

For each stable service identity and key version, a service provisioner will:

1. create or reconcile the service identity with
   `communication_enabled = false`;
2. generate an asymmetric keypair using a cryptographically secure random
   source;
3. create an immutable, project-specific Kubernetes Secret in the service's
   namespace containing `key-id`, `algorithm`, `private-key`, and `public-key`;
4. mount that Secret read-only into only the service container that signs
   requests;
5. persist the key ID, algorithm, public key, fingerprint, activation state,
   and lifecycle metadata in the kernel database; and
6. allow a separate administrative action to enable communication only after
   the Secret and database public-key record match.

The public key may be retained in the Secret as requested so the workload can
inspect or publish its identity consistently. It is not confidential. The
private key is confidential and MUST NOT be stored in the kernel database.
The kernel MUST verify requests from its database registry and MUST NOT receive
Kubernetes Secret-read permission merely to authenticate requests.

The first implementation uses one active service key shared by replicas of the
same stable service identity. Per-replica keys may be introduced later through
a separate decision.

### Reconciliation and failure safety

Provisioning is an idempotent reconciled workflow, not a cross-system
transaction. Its durable states are `pending_key`, `pending_registry`,
`disabled`, `enabled`, and `failed`. `enabled` is reachable only when the
Secret exists, the public-key record is active, and their key IDs, algorithms,
and fingerprints match.

A retry reuses the service ID and provisioning idempotency key. It must not
silently replace an existing private key. Orphaned Secrets and incomplete
database records remain disabled and are reconciled or explicitly cleaned up
with an audit record.

### Rotation

Rotation creates a new key ID and a new immutable Secret. The new public key is
registered, service replicas roll to the new Secret, and both public keys may
be accepted for a bounded overlap. The old key is then revoked in PostgreSQL;
the old Secret may be deleted after the rollout and replay window. Public-key
history and the rotation audit record are retained.

### Kubernetes security requirements

- Secret manifests containing real key material MUST NOT be committed to Git.
- Secret data MUST be encrypted at rest in the Kubernetes control plane.
- The provisioner's RBAC MUST be namespace-scoped and limited to the named
  Secret resources it manages wherever practical.
- Service accounts and workloads MUST NOT receive `list` or `watch` access to
  Secrets; the service reads its own mounted Secret from the filesystem.
- A Pod specification MUST mount the Secret only into the signing container,
  read-only, and MUST NOT place the private key in environment variables.
- Provisioning logs and audit records MUST contain key IDs and fingerprints,
  never private-key material.

## Consequences

### Positive

- A service receives a signing key automatically when it is created.
- The private key stays at the workload boundary while the kernel remains able
  to verify requests during Kubernetes API disruption.
- Immutable Secrets prevent in-place credential changes that running Pods may
  observe inconsistently.
- Disabled-by-default reconciliation prevents partial provisioning from
  granting communication.

### Negative

- The provisioner is a high-value component because it generates private keys
  and writes Secrets.
- PostgreSQL and Kubernetes state require explicit reconciliation and orphan
  handling.
- Rotation requires a rollout and a bounded two-key verification window.
- Kubernetes Secret encryption and restrictive RBAC are cluster-level
  operational requirements, not properties of the manifest alone.

### Follow-up work

- Choose the initial asymmetric algorithm and serialized key format.
- Define the public-key registry and provisioning-state migrations.
- Implement the idempotent provisioner and narrowly scoped RBAC.
- Add conformance tests for creation, retry, partial failure, mismatch,
  rotation, revocation, and rollout recovery.

## Validation

The decision is working when creating a service produces an immutable Secret
and matching database public-key record without exposing the private key;
partial failure leaves communication disabled; retries do not create a new key
unexpectedly; and rotation can revoke the old key without interrupting valid
requests from the rolled-out service.
