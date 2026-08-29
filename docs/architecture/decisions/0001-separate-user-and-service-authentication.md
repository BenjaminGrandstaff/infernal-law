# ADR-0001: Separate user and service authentication

- Status: Superseded
- Date: 2026-08-28
- Deciders: Project owner
- Related: Superseded by ADR-0002; ILK-001, ILK-002, ILK-008, ILK-012, ILK-013

## Context

The kernel needs a trustworthy identity for every governed operation, but user
authentication and service-to-service authentication have different
credentials, lifecycle, threat models, and operating concerns. Putting both in
the kernel would broaden its security boundary and require it to manage user
passwords, sessions, recovery, and identity-provider integrations.

Workers and backend services already require a stable kernel identity and a
strong machine-verifiable credential. Network location alone is not a valid
trust signal.

## Decision drivers

- Keep the kernel's trusted computing base narrow.
- Authenticate every service request without trusting network location.
- Keep private keys and user credentials outside the kernel.
- Support explicit admission, rotation, revocation, audit, and replay defense.
- Preserve a stable service identity when credentials change.

## Considered options

1. Authenticate users and services directly in the kernel.
2. Trust an ingress proxy or private network to identify callers.
3. Delegate user authentication and authenticate only service principals in
   the kernel with registered public keys.

## Decision

Infernal-Law will use option 3.

User authentication is a separate service responsibility. The kernel accepts
only service principals, including workers, for governed operations. Each
request is signed using a private key retained by the calling service and
verified using an active public key registered in the kernel.

Service and key admission are explicit backend commands. Those commands are
themselves authenticated, authorized, idempotent, audited, and bootstrapped
from an out-of-band administrative trust anchor. Admission and operation-level
authority remain separate decisions.

## Consequences

### Positive

- The kernel does not store reusable user credentials or service private keys.
- Compromise of network location does not automatically grant kernel access.
- Service identity remains stable through key rotation.
- Key use and administrative changes can be attributed and audited.

### Negative

- A separate user-authentication service must be deployed and operated.
- Signed-envelope canonicalization, clock handling, replay storage, rotation,
  and bootstrap procedures add implementation complexity.
- Existing deployments with human identity records would require an explicit
  migration before adopting the service-only model.
- User-originated provenance is an assertion made by an authenticated service,
  not a user credential verified by the kernel.

### Follow-up work

- Complete the sequence in the
  [service-authentication design](../service-authentication.md).
- Record the initial signing algorithm and canonical encoding in a separate
  ADR after security review.
- Define the external user-authentication service contract outside the kernel.

## Validation

The decision is working when governed endpoints reject unsigned, replayed,
altered, unknown-key, revoked-key, disabled-service, and unauthorized requests,
while key rotation preserves stable service identity and audit attribution.
