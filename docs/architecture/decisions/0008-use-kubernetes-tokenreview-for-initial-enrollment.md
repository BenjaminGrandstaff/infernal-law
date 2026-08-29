# ADR-0008: Use Kubernetes TokenReview for initial enrollment

- Status: Accepted
- Date: 2026-08-28
- Supersedes: The enrollment portion of [ADR-0002](0002-external-kubernetes-authenticator.md)
- Complements: [ADR-0005](0005-use-ephemeral-per-instance-service-keys.md), [ADR-0006](0006-store-instance-public-keys-in-postgresql.md)

## Context

A new service instance has an ephemeral Ed25519 key but that key is not yet
trusted. Accepting a self-signed key would let any process create an identity.
The kernel needs a bootstrap proof tied to the workload Kubernetes actually
started, without turning the Kubernetes bearer token into the ongoing service
credential or storing it in PostgreSQL.

## Decision

Initial enrollment is kernel-initiated and fail-closed:

1. The kernel creates a cryptographically random, PostgreSQL-backed challenge
   for the expected stable service ID. It expires after 30 seconds and can be
   consumed only once.
2. The candidate submits its proposed instance/key IDs, Ed25519 public key,
   HTTPS endpoint, claimed Pod UID, and a projected ServiceAccount token whose
   audience is exactly `infernal-law-enrollment`.
3. The candidate signs a versioned, length-prefixed proof binding the challenge,
   stable service ID, instance ID, key ID, public key, endpoint, Pod UID, and
   SHA-256 digest of the bearer token.
4. The kernel verifies proof of key possession, submits the token to Kubernetes
   TokenReview with the required audience, and requires an authenticated result
   containing the expected audience and bound Pod UID.
5. The verified namespace, ServiceAccount name, and ServiceAccount UID must map
   to that stable service ID in an enabled PostgreSQL enrollment binding.
6. The kernel atomically marks the challenge consumed, then writes the public
   key and bounded instance lease through the existing registry contract. If
   registration fails, the candidate must request a new challenge.

The bearer token is never logged, returned in an error, persisted, or used for
normal service requests. After enrollment, direct communication uses the
ephemeral Ed25519 credential. The private key remains only in the instance.

The kernel ServiceAccount receives only `create` on
`authentication.k8s.io/tokenreviews`. Its API credential is an explicit,
short-lived projected token volume; automatic ServiceAccount token mounting
remains disabled.

## Consequences

- Enrollment is rooted in Kubernetes workload identity and database policy,
  not possession of an unregistered key.
- A copied enrollment token alone is insufficient because the response must
  prove possession of the proposed private key and match the token's Pod UID.
- Deleted bound Pods and expired projected tokens fail TokenReview.
- Replay is rejected by the single-use, expiring database challenge.
- Enrollment depends on Kubernetes API availability; failure does not bypass
  authentication.
- Administrators need a separate, narrowly privileged path to create disabled
  workload bindings and enable them after review.

## References

- [Kubernetes ServiceAccount token projection](https://kubernetes.io/docs/concepts/storage/projected-volumes/#serviceaccounttoken)
- [Kubernetes TokenReview API](https://kubernetes.io/docs/reference/kubernetes-api/definitions/token-review-v1-authentication/)
- [Kubernetes ServiceAccount administration](https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/)
