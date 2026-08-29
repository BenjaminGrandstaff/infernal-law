# ADR-0002: Use an external Kubernetes service authenticator

- Status: Superseded
- Date: 2026-08-28
- Deciders: Project owner
- Supersedes: [ADR-0001](0001-separate-user-and-service-authentication.md)
- Related: Superseded by ADR-0003; ILK-001, ILK-002, ILK-008, ILK-012, ILK-013

## Context

ADR-0001 separated user authentication from service authentication but placed
per-service public-key registration and backend admission commands inside the
kernel. The desired deployment model is more Kubernetes-native and keeps
credential verification and service enrollment outside the kernel.

Kubernetes already gives workloads namespaced ServiceAccount identities and
short-lived projected tokens. A separate component can authenticate those
tokens and consult kernel admission state without making the kernel an identity
provider or service-registration API.

## Decision drivers

- Keep credential verification outside the governance kernel.
- Use Kubernetes workload identities and short-lived credentials.
- Make service admission a simple, durable database state transition.
- Prevent callers from bypassing the external authenticator.
- Preserve independent kernel authorization and audit attribution.
- Separate read-only authentication from privileged admission changes.

## Considered options

1. Keep per-service public keys and backend admission commands in the kernel.
2. Trust headers inserted by an ingress or authentication proxy.
3. Use an external Kubernetes authenticator, a database-backed admission flag,
   and a cryptographically verified internal assertion.

## Decision

Infernal-Law will use option 3.

Calling workloads authenticate to a separate authenticator using short-lived,
audience-bound Kubernetes ServiceAccount tokens. The authenticator validates
tokens using the Kubernetes TokenReview API, maps the verified workload to a
stable kernel service identity, and checks that identity's database admission
flag.

For an admitted service, the authenticator produces a short-lived signed
assertion bound to the submitted request and forwards the request to the
kernel. The kernel verifies the assertion's signature, issuer, audience,
expiry, request digest, and replay identifier. It does not trust a plain
forwarded identity header or network location.

A separate registrar/controller owns admission changes. It changes the
database flag through a constrained database function that atomically appends
admission history. The authenticator has read-only access to admission state;
the kernel has no service-enrollment endpoint.

Admission means the service may request kernel operations. ILK-002 Authority
still decides whether it may perform a specific operation and defaults to deny.

## Consequences

### Positive

- Workloads use Kubernetes-managed, short-lived credentials.
- The kernel contains no user or workload credential-verification logic.
- Service admission can be reconciled by a Kubernetes controller or operated
  by a small administrative program.
- Database roles can separate authentication reads from admission writes.
- The kernel still verifies cryptographic proof and does not trust headers.

### Negative

- The authenticator is a security-critical availability dependency.
- TokenReview requires narrowly scoped Kubernetes API access.
- The internal assertion format, signing-key rotation, and replay storage must
  be designed and operated securely.
- Database admission state and Kubernetes ServiceAccount mappings must be
  reconciled when workloads move between namespaces or clusters.
- NetworkPolicy enforcement depends on the cluster network plugin and cannot
  replace assertion verification.

### Follow-up work

- Implement the [Kubernetes service-authentication design](../kubernetes-service-authentication.md).
- Define the signed internal assertion format and algorithm in an ADR.
- Add the service registry, admission-history schema, and constrained database
  roles/function.
- Build separate authenticator and registrar/controller deployments.

## Validation

The decision is working when valid admitted ServiceAccounts reach governed
operations, disabled or unknown services are rejected, direct calls and forged
headers fail, altered or replayed assertions fail, and each admitted request is
audited under the mapped stable service identity.
