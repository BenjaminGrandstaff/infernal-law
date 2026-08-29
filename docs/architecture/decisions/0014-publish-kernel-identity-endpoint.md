# ADR-0014: Publish kernel signing identity via an unauthenticated endpoint

- Status: Accepted
- Date: 2026-08-29
- Deciders: Project owner
- Complements: [ADR-0003](0003-direct-signed-service-rest.md), [ADR-0005](0005-use-ephemeral-per-instance-service-keys.md), [ADR-0013](0013-external-stateless-policy-evaluator-for-authority.md)
- Related: ILK-001, ILK-002

## Context

ADR-0013 requires the kernel to sign its outbound call to the policy
evaluator, so the evaluator can confirm the request really came from the
kernel and not from anything else that happened to reach its address. The
kernel already has the machinery to *sign* such a call: `service_requests.rs`
implements the full Ed25519/RFC 9421 signing side of the ADR-0003 profile
today, exercised by every existing contract test that round-trips a signed
request against the verifier. Signing is not the gap.

Verifying is. A signed message already carries its own key material inline —
`SignedServiceRequest` embeds a `keyid`, and `SignedHandshakeChallenge`
embeds the kernel's full `InstancePublicKey` directly in the challenge. An
embedded, self-asserted key proves nothing by itself; a verifier needs an
independent way to confirm that key is one a genuine kernel instance is
currently vouching for. For ordinary services, that independent channel
already exists: the kernel's own PostgreSQL-backed instance registry
(ADR-0006). For the kernel's *own* key, no equivalent exists — the kernel
does not register itself in its own registry, and ADR-0005 only says a
handshake target "verifies the kernel signature against its configured
kernel trust anchor" without ever specifying how that trust anchor is
established or kept in sync with a key that rotates on every process
restart. That gap is real, not a deliberate simplification: it is the most
likely reason "production outbound HTTP transport remains pending" for the
handshake reconciler, which has had the same unanswered question since
ADR-0005.

## Decision

The kernel exposes a new route, `GET /v1/kernel-identity`, publishing the
current process's public signing key material:

```json
{
  "algorithm": "ed25519",
  "instance_id": "...",
  "key_id": "...",
  "public_key": "<url-safe base64, no padding>",
  "fingerprint": "<url-safe base64, no padding>"
}
```

This introduces no new trust primitive. A public key is not confidential —
ADR-0005 already established that norm for the instance registry ("called a
secret manager... not because a public key is confidential"). Any caller
that needs to verify a kernel-signed message fetches this once, caches it,
and re-fetches on a verification failure — the same fetch/cache/refresh-on
mismatch pattern used broadly for public key distribution (JWKS being the
most familiar instance). A verification failure after a successful earlier
fetch is a meaningful signal on its own: the kernel process restarted and
rotated its key, not that the message was forged.

The route is deliberately outside governed-request authentication, joining
`/health/live` and `/health/ready`: a caller cannot authenticate to the
kernel via a mechanism that itself depends on already knowing the kernel's
key, so this has to be the one deliberately public exception. It returns
only this process's own public signing material — no other service's keys,
no administrative state, nothing else.

### Known limitation: multiple kernel replicas

This endpoint answers "what is *this* kernel process's identity," and per
ADR-0005 every kernel process holds its own independent ephemeral key. Behind
a load-balanced, multi-replica kernel Service, a caller hitting
`/v1/kernel-identity` through the shared address may land on a different
replica than the one that actually signed the message it is trying to
verify — the two replicas have different keys, and the single-key response
this ADR defines cannot represent that.

Correct multi-replica verification needs kernel instances to publish their
keys somewhere every replica can read from, mirroring how ordinary service
instances already publish into the PostgreSQL instance registry (ADR-0006),
so that any replica answering `/v1/kernel-identity` can return the complete
currently-active set rather than only its own key. That is explicitly not
built here. This decision is correct and sufficient for a single kernel
replica — this project's only exercised deployment shape so far — and
intentionally leaves multi-replica correctness as follow-up work rather than
speculatively building a kernel-instance registry with no caller to
validate it against yet.

## Consequences

### Positive

- Closes the one real gap in ADR-0013's authenticated-channel requirement:
  the evaluator (or any future verifier of kernel-signed messages, including
  the handshake reconciler's outbound transport) has a concrete way to
  obtain a trustworthy kernel key without static configuration that breaks
  on every kernel restart.
- No new trust primitive, no secret exposure: this is the same
  "publish the public key, keep the private key in-process" model the kernel
  already applies to every other service.
- Consistent with the existing public-route precedent
  (`/health/live`, `/health/ready`).

### Negative

- Reveals that a kernel instance is reachable and running at a given
  address — the same minor operational exposure `/health/live` already
  accepts, not a new category of risk.
- Only correct for a single kernel replica until the multi-replica follow-up
  (a shared kernel-instance key registry) is built; deploying multiple kernel
  replicas today makes signature verification against this endpoint
  unreliable.

## Validation

The decision is working when: a caller with no prior configuration can fetch
`/v1/kernel-identity`, use the returned key to verify a message signed by
that same kernel process, and detect a restarted/rotated kernel by a
verification failure that a re-fetch resolves; and the endpoint reveals
nothing beyond this process's own public signing material.
