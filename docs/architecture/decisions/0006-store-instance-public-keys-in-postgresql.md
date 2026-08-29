# ADR-0006: Store instance public keys and leases in PostgreSQL

- Status: Accepted
- Date: 2026-08-28
- Deciders: Project owner
- Supersedes: The external secret-manager registry placement in [ADR-0005](0005-use-ephemeral-per-instance-service-keys.md)
- Complements: [ADR-0003](0003-direct-signed-service-rest.md), [ADR-0005](0005-use-ephemeral-per-instance-service-keys.md)
- Related: ILK-001, ILK-008, ILK-010, ILK-012, ILK-013

## Context

The kernel owns service-instance registration, lease renewal, handshake state,
admission, and signature verification. An external secret manager would split
authoritative state across two systems even though public keys are not secret.
PostgreSQL is already the kernel's durable system of record and can update the
public key, lease, and audit outcome transactionally.

The private half remains fundamentally different: it belongs only to one
running service process and must never enter PostgreSQL.

## Decision drivers

- Keep kernel-owned state in the kernel database.
- Make registration, lease revision, and audit atomic.
- Avoid an unnecessary external secret-manager dependency.
- Preserve per-instance ephemeral private keys.
- Prevent services from directly mutating kernel tables.
- Make stale-instance filtering deterministic across kernel replicas.

## Decision

PostgreSQL is the authoritative registry for service-instance public keys and
leases. Services access it only through authenticated kernel contracts.

The logical model contains:

- `service_instances`: stable service ID, unique instance and boot IDs,
  endpoint, protocol version, registration state, lease expiry, monotonically
  increasing lease revision, registration/renewal times, and terminal time;
- `service_instance_keys`: immutable key ID, owning instance ID, algorithm,
  public-key bytes, fingerprint, validity interval, and revocation time; and
- append-only registration, renewal, expiry, revocation, mismatch, and
  handshake audit records.

An instance and key ID are never reassigned. Key rows are not updated in place
to contain different key material. Expired or revoked records remain available
for audit but are ineligible for new authentication or delivery.

### Initial registration

Possession of a newly generated private key is not enough to claim a stable
service ID. Initial registration MUST use a separate enrollment credential or
platform workload proof already mapped to that service identity. The exact
bootstrap mechanism remains a separate decision.

After validating that proof, the kernel performs one database transaction that:

1. verifies the stable service exists and the enrollment proof is allowed to
   register for it;
2. inserts the create-only instance and public-key records;
3. establishes a bounded initial lease;
4. appends the security audit record; and
5. returns the registration result and handshake requirements.

A retry with the same idempotency key and identical registration returns the
original result. Reusing an instance ID, key ID, or idempotency key with
different material fails closed.

### Lease renewal and termination

After registration, renewal requests MUST be fresh and signed by the currently
registered instance key. A renewal conditionally increments `lease_revision`
and updates `lease_expires_at` in the same transaction as its audit record.
Concurrent or stale revisions cannot extend a lease.

Graceful termination revokes eligibility immediately and records the outcome.
Abrupt failure leaves the record in place until its lease expires. Expiry is a
queryable state derived from database time; deleting a row is not required to
make an instance ineligible.

### Kernel discovery

Every kernel replica queries PostgreSQL for active subscriptions joined to
unexpired, non-revoked instance keys. It then performs the fresh
proof-of-possession handshake from ADR-0005. The database public key is
authoritative; a key returned by a network endpoint is not.

Eligibility for delivery requires a fresh database lease and handshake in
addition to communication admission, subscription, readiness, and capacity.

## Consequences

### Positive

- Registration, leases, and audit share one transaction boundary.
- Kernel replicas observe one authoritative registry.
- Public-key discovery remains available whenever the kernel database is
  available.
- No secret-manager product or Kubernetes Secret access is required for
  instance public keys.

### Negative

- Registration and heartbeat traffic add database writes.
- Database availability now gates enrollment and lease renewal.
- Lease indexes and cleanup/history retention require operational care.
- A secure, non-circular initial enrollment mechanism is still required.

### Follow-up work

- Define the initial enrollment credential or workload-proof mechanism.
- Add instance, key, lease, and audit migrations with uniqueness and expiry
  constraints.
- Implement repository contracts and an in-memory test adapter.
- Add signed registration/renewal HTTP contracts and concurrency tests.
- Define lease duration, renewal cadence, clock policy, and history retention.

## Validation

The decision is working when registration atomically stores a public key,
bounded lease, and audit record; stale or conflicting renewals fail; all kernel
replicas discover the same eligible instances; expired records cannot receive
delivery; and no private key exists in PostgreSQL.
