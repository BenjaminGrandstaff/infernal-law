# Direct signed service protocol

> Status: Accepted architecture; initial enrollment implemented
> Last reviewed: 2026-08-28
> Owners: TODO

## State dimensions

Service state is deliberately separated into independent dimensions:

| Dimension | Example state | Owner | Meaning |
| --- | --- | --- | --- |
| Identity | Stable service ID | Kernel identity registry | Who the service is |
| Credential | Active or revoked public key | Key registry | Which signatures can authenticate it |
| Admission | `communication_enabled` | Administrative database writer | Whether it may communicate with the kernel at all |
| Authority | Operation grants and denials | Kernel authority policy | What an admitted service may do |
| Subscription | Active event-type interests | Service through signed REST API | Which committed events it requests |
| Liveness | Alive or dead | Health evaluator/Kubernetes | Whether the process needs restart |
| Readiness | Ready or not ready | Health evaluator/Kubernetes | Whether the process should receive traffic |
| Capacity | Available, saturated, or draining | Hub health/backpressure model | How much new event/work delivery it can accept |

No dimension implicitly changes another. In particular:

- `communication_enabled = true` does not mean healthy or authorized;
- healthy does not mean admitted or authorized;
- an inactive subscription does not disable service communication; and
- overload pauses new delivery but does not revoke identity or keys.

## Direct REST authentication

Services communicate directly with the kernel/hub over HTTPS. Requests follow
the HTTP Message Signatures model and include:

- `Signature-Input` describing covered components, key ID, creation time,
  expiration time, and nonce;
- `Signature` containing the asymmetric signature;
- `Content-Digest` containing a SHA-256 digest when a body is present;
- a stable service ID;
- a unique request/idempotency ID; and
- the REST method, authority, path, query, and content metadata required by the
  protocol's signature profile.

The private key remains with the calling service. The kernel stores public
keys and lifecycle metadata only. HTTPS remains mandatory for confidentiality;
message signatures provide end-to-end request integrity and authentication.

The exact asymmetric algorithm and key encoding require a separate decision.
No custom construction such as concatenating fields and hashing them is
permitted.

## Per-instance key creation and public-key registry

Every service process generates a unique keypair before becoming ready. The
private key remains inside that one process and is never stored in a Kubernetes
Secret, external secret manager, PostgreSQL, image, or durable volume. A process
restart, including a container restart within the same Pod, creates a new
instance ID and keypair. In-memory key storage is preferred; any required file
must be in instance-private RAM-backed storage.

The service publishes only its public key, fingerprint, algorithm, unique
instance and key IDs, endpoint, creation/expiry times, and short-lived lease to
the kernel's registration contract. The kernel validates a separate enrollment
credential or platform workload proof, then atomically stores the instance,
public key, bounded lease, and audit record in PostgreSQL. A service never
writes these tables directly and cannot overwrite another service's records.

Every kernel process discovers instances belonging to active subscriptions at
startup and continuously afterward. For each candidate, it retrieves the public
key and current lease from PostgreSQL and sends a fresh, kernel-signed
challenge. The service verifies the kernel, signs the challenge and both
parties' instance metadata, and returns the proof. The kernel verifies that
proof against the database key and atomically consumes the challenge nonce.
Only that exact instance becomes `handshake_verified`.

The handshake proves reachability and current private-key possession. It does
not grant admission, authority, readiness, capacity, or a work claim. A failed
instance's subscription remains durable, but delivery pauses until a new
instance publishes a fresh key and completes a new handshake. See
[ADR-0005](decisions/0005-use-ephemeral-per-instance-service-keys.md).
Registry ownership and persistence are specified by
[ADR-0006](decisions/0006-store-instance-public-keys-in-postgresql.md).

Initial trust uses a separate bootstrap flow. The kernel issues a 30-second,
single-use challenge stored as a digest in PostgreSQL. The candidate signs the
challenge together with its proposed key, endpoint, Pod UID, and digest of an
audience-bound projected ServiceAccount token. Kubernetes TokenReview verifies
the token and bound Pod; an enabled PostgreSQL binding maps the verified
namespace, ServiceAccount, and ServiceAccount UID to the stable service ID.
Only then does the kernel register the public key and lease. See
[ADR-0008](decisions/0008-use-kubernetes-tokenreview-for-initial-enrollment.md).

### Initial-enrollment JSON profile

The enrollment transport uses typed JSON DTOs. UUIDs and HTTPS endpoints are
JSON strings. The 32-byte challenge, 32-byte Ed25519 public key, and 64-byte
signature use RFC 4648 URL-safe base64 without padding. The algorithm value is
exactly `ed25519`; unknown JSON fields, malformed UUIDs, other algorithms,
incorrect binary lengths, and non-canonical encodings are rejected.

The submission DTO contains the projected ServiceAccount bearer token and
therefore deliberately has no debug representation. Public error DTOs collapse
authentication failures to `enrollment_rejected` and infrastructure failures
to `internal_error`; neither tokens nor repository messages cross the wire.

`POST /v1/enrollments` is the only initial-enrollment submission route. It
requires an `application/json` media type, rejects transfer encoding and
ambiguous length/type headers, and caps the complete JSON body at 40 KiB before
deserialization. Successful authentication returns `201` with the typed leased
instance record. Malformed input, authentication rejection, and unavailable
infrastructure return typed JSON errors without reflecting request data.
Challenge issuance remains an internal kernel operation used by the future
discovery reconciler. There is deliberately no unauthenticated HTTP endpoint
that lets a caller create challenges for arbitrary service IDs.

## Verification order

For every non-public request, the kernel MUST:

1. parse the signature profile without accepting ambiguous or duplicate
   security fields;
2. locate the stable service identity and named public key;
3. verify key lifecycle and cryptographic signature;
4. verify the content digest and all required covered HTTP components;
5. enforce creation time, expiry, and bounded clock skew;
6. atomically reject or reserve the nonce/request ID for replay protection;
7. check `communication_enabled`;
8. apply ILK-002 authority to the operation and target;
9. execute through mediation and idempotency; and
10. attribute audit, decisions, events, and mutations to the service and key.

Failure at any step rejects the request before governed state mutation. Health
does not bypass these checks.

## No SQL command surface

REST operations are typed kernel commands and queries. No endpoint accepts raw
SQL, database expressions, caller-selected database identifiers, stored
procedure names, or a generic query language that can mutate kernel state.
SQL-shaped or unknown operations are rejected before repository access.

Kernel-owned PostgreSQL adapters may use fixed, parameterized SQL internally.
That persistence detail is not part of the wire protocol, and a service never
receives database credentials through the kernel. See
[ADR-0007](decisions/0007-expose-no-sql-command-surface.md).

## Admission database attribute

`communication_enabled` is a durable administrative attribute on the service
identity or a one-to-one admission record. It defaults to `false`.

Only a narrowly privileged administrative program or database role may change
it. Every change MUST atomically append immutable history containing:

- service ID;
- old and new values;
- administrator identity;
- reason;
- correlation/idempotency ID; and
- committed time.

The kernel and normal services read the attribute but cannot modify it through
ordinary service operations. A disabled service receives a deterministic
admission rejection even if its key and health are valid.

## Subscriptions

An admitted and authorized service manages subscriptions through signed REST
operations:

- `POST /v1/subscriptions` creates an event-type interest;
- `GET /v1/subscriptions` lists the service's interests;
- `DELETE /v1/subscriptions/{id}` disables future delivery without deleting
  history; and
- cursor/replay operations will be versioned separately.

Subscription state is durable and independent of current health. When delivery
is paused for backpressure, the subscription remains active and its cursor does
not advance until delivery is durably accepted under the chosen delivery
protocol.

The typed subscription domain and PostgreSQL repository are implemented.
Subscriptions belong to stable service IDs rather than process instance IDs.
Disabling sets an immutable timestamp and retains history; a later subscription
for the same event type receives a new subscription ID. Signed REST operations,
authorization, and delivery cursors remain pending.

## Health model

The service and hub use one underlying health evaluation with distinct views:

- `/health/live` reports only whether the local process can make progress and
  should remain running.
- `/health/ready` reports whether the process can currently accept normal
  traffic, including critical dependency and overload checks.
- a signed health/capacity report supplies detailed delivery information such
  as `accepting_work`, `max_in_flight`, `current_in_flight`, `available_slots`,
  `observed_at`, and optional `retry_after`.

The Kubernetes readiness response and the hub's capacity decision MUST derive
from the same internal health snapshot so they cannot disagree about whether
the service is accepting new work. The liveness check remains intentionally
minimal; overload alone MUST NOT cause restart loops.

## Backpressure

The hub may deliver a subscribed event or assign new work only when all of the
following are true:

```text
communication_enabled
AND key_is_active
AND instance_lease_is_fresh
AND handshake_is_verified_and_fresh
AND subscription_is_active
AND service_is_ready
AND health_report_is_fresh
AND available_capacity > 0
```

Backpressure behavior:

- not ready, stale health, draining, or zero capacity pauses new delivery;
- the hub respects `retry_after` within configured bounds;
- paused delivery does not delete subscriptions or mark the service dead;
- existing work claims follow their lease/expiry rules rather than being
  reassigned solely because of one failed health check;
- repeated delivery attempts remain idempotent; and
- recovery resumes from the last durably acknowledged cursor.

Health reports are authenticated and timestamped. The hub treats missing or
stale reports as unavailable for new work, not as proof that the service is
dead.

## Required durable records

- service identities;
- public keys with activation, expiry, and revocation metadata;
- unique service-instance, boot, and key IDs;
- enrollment provenance and database lease revisions;
- kernel challenge and successful-handshake records;
- `communication_enabled` plus append-only admission history;
- used nonce/request IDs for the replay window;
- subscriptions and durable delivery cursors;
- latest health/capacity observation and observation time;
- work claims and lease state; and
- audit records for authentication, admission, subscription, and delivery
  decisions.

## Acceptance criteria

- A correctly signed, fresh request from an enabled service reaches authority
  evaluation.
- Two replicas of one service have distinct keys and cannot authenticate as
  each other.
- A restarted process uses a new instance ID and key and must handshake again.
- A kernel startup verifies each reachable subscribed instance without being
  blocked by unavailable subscribers.
- A disabled service is rejected even when its signature and health are valid.
- An unhealthy or saturated enabled service can query permitted APIs, but the
  hub assigns no new subscribed work until readiness/capacity recovers.
- A healthy disabled service receives no governed communication.
- Altering a signed method, path, query, body, digest, timestamp, nonce, or
  request ID causes rejection.
- Replaying a valid signed request cannot repeat its effects.
- Disabling communication and changing health produce separate audit records
  and do not overwrite each other.
- Backpressure pauses and resumes delivery without losing events, duplicating
  committed effects, or deleting subscription state.

## Implementation sequence

1. Choose the signing algorithm, key encoding, fingerprint profile, key
   lifetime, and lease windows.
2. Add PostgreSQL instance, immutable public-key, bounded lease, and audit
   records plus an authenticated registration contract.
3. Rename the current active/disabled identity state to the explicit
   `communication_enabled` admission concept.
4. Add handshake and append-only admission-history records.
5. Implement service-local ephemeral key generation and the mutual discovery
   handshake.
6. Implement the HTTP Message Signatures
   profile with deterministic conformance vectors.
7. Add timestamp, nonce, replay, and idempotency enforcement.
8. Implement signed subscription REST contracts.
9. Define the shared health snapshot and separate live, ready, and capacity
   projections.
10. Implement delivery backpressure and cursor recovery tests.
