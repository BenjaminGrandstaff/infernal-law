# ADR-0003: Use direct signed REST communication

- Status: Accepted
- Date: 2026-08-28
- Deciders: Project owner
- Supersedes: [ADR-0002](0002-external-kubernetes-authenticator.md)
- Related: ILK-001, ILK-002, ILK-008 through ILK-013

## Context

ADR-0002 introduced a separate Kubernetes authenticator between services and
the kernel. The intended model is instead direct REST communication between
registered services and the Infernal-Law hub/kernel. Services authenticate
messages using public/private-key signatures, while a durable database
attribute determines whether a service is currently allowed to communicate.

Communication admission is administrative policy. It must remain distinct
from observed operational health such as alive, ready, overloaded, or stale.
The hub also needs health and capacity information to apply backpressure when
delivering subscription events and assigning work.

## Decision drivers

- Permit direct, independently verifiable service-to-kernel REST requests.
- Avoid trusting network location or an unsigned intermediary header.
- Make administrative communication admission explicit and durable.
- Keep authorization, health, and admission as separate state dimensions.
- Use the same operational health model to protect Kubernetes routing and hub
  work delivery from overloaded or unavailable services.
- Bind signatures to complete messages, timestamps, and replay identifiers.

## Considered options

1. Use an external Kubernetes TokenReview authenticator and internal assertion.
2. Trust mTLS or cluster network identity without message-level signatures.
3. Allow direct HTTPS requests using standardized HTTP message signatures,
   database admission, and health-driven backpressure.

## Decision

Infernal-Law will use option 3.

Each service retains its private key and registers one or more public keys with
the kernel. Direct REST requests use HTTP Message Signatures with creation and
expiration times, a nonce, a key ID, covered request components, and a
SHA-256 content digest. SHA-256 protects content integrity; it is not itself a
public/private-key signature algorithm. The allowed asymmetric signing
algorithm is a separate versioned protocol choice.

The kernel verifies the signature and replay constraints, then checks the
service's durable `communication_enabled` admission attribute. Admission only
allows communication; ILK-002 Authority still decides whether the service may
perform the requested operation.

The hub maintains separate operational health and capacity state. Liveness
answers whether a process should be restarted. Readiness answers whether it can
accept traffic. Capacity governs subscription and work-delivery backpressure.
Healthy state never grants admission, and disabling communication does not mean
the process is dead.

## Consequences

### Positive

- Every direct request is cryptographically attributable to a service key.
- Admission can be toggled without deleting identity, subscriptions, or audit
  history.
- Operational failures do not silently change security policy.
- The hub can pause new deliveries while preserving subscriptions and work.
- Kubernetes readiness and hub delivery use one underlying health evaluation.

### Negative

- Per-instance key generation, isolation, public-key enrollment, expiry, and
  revocation remain operational responsibilities.
- Timestamp validation requires bounded clock skew.
- Replay protection needs durable or safely partitioned nonce state.
- Health and capacity reporting must resist stale or dishonest reports.
- HTTP transformations by proxies must preserve the components covered by the
  signature profile.

### Follow-up work

- Implement the [direct service protocol](../direct-service-protocol.md).
- Choose the initial asymmetric signing algorithm and key encoding.
- Add admission, public-key, replay, subscription, and health/capacity schema.
- Implement health-driven event and work backpressure.

## Validation

The decision is working when signed direct requests succeed only for enabled
services with valid keys and authority; altered, expired, future, or replayed
messages fail; and the hub pauses new subscription/work delivery when readiness
or capacity falls without changing admission or deleting subscriptions.
