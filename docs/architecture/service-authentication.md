# Service authentication

> Status: Superseded by [ADR-0002](decisions/0002-external-kubernetes-authenticator.md)
> Last reviewed: 2026-08-28
> Owners: TODO

This document preserves the original per-service public-key design. The current
design is [Kubernetes service authentication](kubernetes-service-authentication.md).

## Boundary

Infernal-Law authenticates **service principals**, including workers. It does
not register users, store user credentials, issue user sessions, or decide
whether a human successfully authenticated. Those responsibilities belong to a
separate user-authentication service.

When work originates from a user, the authentication service or another
trusted backend calls the kernel as its own service identity. It may attach an
external user subject as signed provenance. The kernel records that provenance
as an assertion by the calling service; it does not treat the external subject
as a kernel credential or independently grant it authority.

## Zero-trust properties

The design does not grant trust because a caller is inside a cluster, uses a
known IP address, or reaches a private network. For every non-public request,
the kernel MUST:

1. identify the claimed service and signing key;
2. verify a signature over the complete canonical request envelope;
3. confirm the service and key are registered, active, and valid at the request
   time;
4. reject expired, future-dated, or replayed requests;
5. independently authorize the requested operation and target;
6. bind the verified service context to audit, decision, event, and mutation
   records; and
7. perform the governed operation through the mediation boundary.

TLS remains mandatory for confidentiality and transport integrity. Request
signatures do not replace TLS.

## Key ownership

- A service generates and retains its private key.
- A private key MUST NOT be transmitted to or stored by the kernel.
- The kernel stores the service ID, key ID, public key, algorithm identifier,
  lifecycle status, and validity interval.
- Multiple active public keys MAY exist during rotation.
- Revoking a key prevents new requests but does not erase historical evidence
  that the key signed earlier requests.
- Algorithms and key encodings MUST come from an explicit allowlist. The exact
  initial algorithm and encoding require a separate security decision before
  implementation.

## Signed request envelope

The signature MUST cover an unambiguous canonical representation containing at
least:

| Field | Purpose |
| --- | --- |
| Protocol version | Supports controlled evolution of verification rules |
| Service ID | Identifies the calling kernel principal |
| Key ID | Selects the registered public key |
| Issued-at and expiry times | Bounds credential freshness |
| Nonce | Prevents replay within the validity window |
| Request or idempotency ID | Connects authentication to retry semantics |
| Operation | Binds the signature to the requested kernel command |
| Target | Prevents a valid signature from being reused for another resource |
| Payload digest | Detects body substitution or modification |

The canonical encoding, clock-skew allowance, maximum validity window, payload
digest algorithm, and nonce-retention period MUST be fixed and versioned before
the verifier is implemented. Concatenating fields without a canonical encoding
is prohibited.

## Backend administration commands

Service admission and key lifecycle are governed backend commands:

- `RegisterService` creates a disabled service identity.
- `AddServiceKey` attaches a public key to a service.
- `AllowService` activates a service after its required key material exists.
- `RotateServiceKey` adds a replacement key without changing the service ID.
- `RevokeServiceKey` rejects future signatures from one key.
- `DisableService` rejects all future requests from the service.

An allow command admits an identity; it does **not** grant every operation.
Operation-level permission remains the responsibility of ILK-002 Authority and
defaults to deny.

Every administration command MUST be authenticated, authorized, idempotent,
audited, and committed atomically with any resulting event. Normal services
MUST NOT be able to approve themselves or their own replacement keys unless a
specific authority policy permits it.

## Bootstrap

The first administrative trust anchor cannot depend on an already admitted
service. Deployment MUST provision one bootstrap administrative public key or
an equivalent external trust anchor through a controlled out-of-band process.
The corresponding private key remains outside the kernel.

Bootstrap authority MUST be narrowly scoped to service and key administration,
audited from first use, rotatable, and removable after normal administrative
services are established. An unauthenticated backend endpoint is prohibited.

## Durable records

The design requires durable records for:

- service identities and lifecycle state;
- public keys and their lifecycle intervals;
- authenticated request IDs and nonces used for replay prevention;
- administrative commands and outcomes; and
- audit records containing the verified service ID and key ID.

Private keys and reusable user credentials are explicitly excluded.

## Acceptance criteria

- A registered, active service with an active key can produce a verifiable
  request, subject to a separate authority decision.
- An unknown, disabled, expired, revoked, or incorrectly signed key is rejected
  before governed state is read or changed.
- Changing the operation, target, payload, expiry, or request ID invalidates the
  signature.
- Replaying the same signed envelope cannot repeat an effect.
- Key rotation does not change the stable service ID.
- An administration command cannot succeed without verified administrative
  identity and authority.
- External user credentials presented directly to the kernel are rejected.
- Audit history identifies the verified service and key used for every
  security or governance operation.

## Implementation sequence

1. Refactor ILK-001 from human/service/worker identities to service principals,
   with workers represented as a service role or profile.
2. Add durable public-key and service-lifecycle records.
3. Define and approve the signing algorithm and canonical envelope in an ADR.
4. Implement pure signature, freshness, and replay-verification tests.
5. Add authenticated backend administration commands.
6. Connect verified service context to ILK-002 Authority, ILK-008 Audit,
   ILK-012 Idempotency, and ILK-013 Mediation.
7. Add end-to-end rejection tests before exposing governed commands.
