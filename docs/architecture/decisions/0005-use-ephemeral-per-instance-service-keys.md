# ADR-0005: Use ephemeral per-instance service keys

- Status: Accepted
- Date: 2026-08-28
- Deciders: Project owner
- Supersedes: [ADR-0004](0004-provision-service-keys-with-kubernetes-secrets.md)
- Complements: [ADR-0003](0003-direct-signed-service-rest.md)
- Registry placement superseded by: [ADR-0006](0006-store-instance-public-keys-in-postgresql.md)
- Kernel trust anchor mechanism defined by: [ADR-0014](0014-publish-kernel-identity-endpoint.md)
- Related: ILK-001, ILK-008, ILK-010, ILK-012, ILK-013

## Context

Each running service instance needs a unique credential that no other service
or replica can use. Its private key must disappear when that instance exits.
A persistent Kubernetes Secret cannot provide that property because it
outlives the process and may be mounted by replacement Pods.

Every new kernel instance must also discover currently subscribed service
instances and establish that they are reachable and possess the private half
of the public key registered for them. Discovery cannot treat a network
endpoint or a public key returned by that endpoint as proof of identity.

## Decision drivers

- Give every service instance a unique keypair and instance ID.
- Never expose a private key to another service, the kernel, PostgreSQL,
  Kubernetes Secrets, or the external secret manager.
- Destroy the only usable private-key copy when its service process exits.
- Make kernel startup discovery authenticated and replay-resistant.
- Keep subscriptions durable while instance presence remains short-lived.
- Recover safely from kernel or service restarts without reusing credentials.

## Considered options

1. Share one persistent Kubernetes Secret across all replicas of a service.
2. Store a distinct private-key Secret for each Pod.
3. Generate a keypair inside each service instance, retain the private key only
   in that process, and publish only its public key through a secret-manager
   registry.

## Decision

Infernal-Law will use option 3.

### Instance key lifecycle

Each service process MUST generate a fresh asymmetric keypair from a
cryptographically secure random source before becoming ready. The key belongs
to a unique `(service_id, instance_id, key_id, boot_id)` tuple and MUST never be
reused by another process start, Pod, or replica.

The private key remains inside the signing process and is never exported. If a
library requires file-backed key material, the file MUST live in a
memory-backed, instance-private location and be removed on shutdown; in-memory
storage is preferred. A container restart in the same Pod is a new instance
and generates a new key. Process termination destroys the only private-key
copy. Crash dumps, core dumps, logs, metrics, and diagnostics MUST exclude key
material.

A self-detected terminal failure MUST stop request signing, zeroize the key
where supported, and terminate the instance. Temporary unready, draining, or
overloaded states only pause delivery and do not rotate the key. External
observers cannot prove erasure after an abrupt failure, so they fail closed by
expiring the instance lease and handshake.

The service publishes only the public key and the following signed metadata to
the configured secret-manager registry:

- stable service ID and unique instance ID;
- key ID, algorithm, encoded public key, and fingerprint;
- boot ID, creation time, expiry time, and lease revision;
- service endpoint and protocol version; and
- registration provenance supplied by the platform workload identity.

Publication MUST use an independently authenticated platform identity and a
compare-and-set or create-only operation scoped to that service. A service may
not write another service's registry path. Public-key records are leased and
short-lived; heartbeat renewals extend presence without extending the signing
key beyond its configured maximum lifetime.

The public-key registry is called a secret manager because it supplies the
managed registry and access policy, not because a public key is confidential.
Private keys MUST NOT be written there or to Kubernetes Secrets. PostgreSQL may
retain public-key fingerprints, handshake results, expiry/revocation state,
and audit history, but never private keys.

### Kernel startup discovery and handshake

Every kernel process has its own authenticated kernel identity and signing key.
On startup, and continuously afterward, it performs this reconciliation:

1. Load active subscriptions and their stable service IDs from PostgreSQL.
2. Resolve candidate ready instances through the service directory or
   Kubernetes discovery; do not infer identity from an IP address.
3. Read each candidate's public-key record from the secret manager using its
   service and instance IDs.
4. Send a kernel-signed handshake challenge containing a fresh random nonce,
   kernel instance ID, target service and instance IDs, creation time, expiry,
   and requested protocol version.
5. The service first verifies the kernel signature against its configured
   kernel trust anchor, then signs a response over the challenge nonce, both
   instance identities, its key ID, endpoint, boot ID, public-key fingerprint,
   current time, and supported protocol/capabilities.
6. The kernel verifies the response using the public key fetched from the
   secret manager, verifies the platform registration provenance and lease,
   atomically consumes the challenge nonce, and checks the response before its
   expiry.
7. Only then mark that exact instance `handshake_verified` and eligible for
   health evaluation and subscribed delivery.

The key supplied by the endpoint is never authoritative. A mismatch with the
secret-manager record fails closed and produces an audit event. Handshake
success proves current key possession and reachability; it does not grant
communication admission, operation authority, readiness, capacity, or a work
claim.

Kernel discovery is fan-out reconciliation, not a one-time startup barrier.
One unavailable service MUST NOT prevent the kernel from starting. Its durable
subscription stays active, but delivery to that instance remains paused and is
retried with bounded exponential backoff and jitter. New instances and public
key rotations trigger the same handshake.

### Failure and expiry

When a service instance exits, it cannot explicitly prove destruction, so the
kernel MUST rely on loss of connectivity plus a short public-key lease and
fresh health requirements. An old public record is not proof that an instance
is alive. After lease or handshake expiry, the instance is ineligible for new
delivery even if its stable service remains subscribed and
`communication_enabled`.

Graceful shutdown may revoke the public-key lease immediately. Abrupt failure
lets the lease expire. A restarted process creates a new instance ID and key,
publishes a new public record, and completes a new handshake.

## Consequences

### Positive

- Compromise of one replica's key does not impersonate another replica.
- Private key material is not persisted and disappears with the signing
  process.
- The kernel verifies live possession instead of trusting discovery metadata.
- Durable subscriptions survive ephemeral instance and kernel restarts.

### Negative

- Service startup now depends on key generation and public-key registration.
- Kernel and service identities need their own trust anchors for mutual
  handshake authentication.
- A secret-manager outage prevents new-instance enrollment and re-handshake,
  although already verified sessions may continue only within bounded leases.
- Ephemeral keys increase registry writes, handshakes, audit records, and
  operational complexity.
- Process memory cannot be guaranteed erased after hostile node or runtime
  compromise; node, runtime, dump, and swap hardening remain required.

### Follow-up work

- Select the secret-manager implementation and define its path and access
  policy model.
- Select the asymmetric algorithm, key encoding, maximum key lifetime, lease,
  handshake, and clock-skew windows.
- Define how services receive and rotate the kernel trust anchor.
- Specify service discovery and the handshake REST schema.
- Test replay, substitution, stale leases, key loss, concurrent kernel startup,
  partial discovery, registry outage, restart, and replica isolation.

## Validation

The decision is working when two replicas always have different keys; neither
can sign as the other; killing and restarting one process produces a new
instance and key; no private key exists in Kubernetes Secrets, the secret
manager, or PostgreSQL; and every new kernel verifies subscribed live instances
with a fresh mutual challenge before delivering events.
