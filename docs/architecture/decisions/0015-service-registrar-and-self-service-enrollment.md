# ADR-0015: Split enrollment into a self-service nonce and an out-of-band registrar

- Status: Accepted
- Date: 2026-09-04
- Deciders: TODO
- Related: [ADR-0002](0002-external-kubernetes-authenticator.md),
  [ADR-0007](0007-expose-no-sql-command-surface.md),
  [ADR-0008](0008-use-kubernetes-tokenreview-for-initial-enrollment.md),
  [ADR-0013](0013-external-stateless-policy-evaluator-for-authority.md)

## Context

ADR-0008 specifies a fail-closed enrollment handshake and the kernel implements
it correctly: `POST /v1/enrollments` verifies proof of key possession, submits
the workload token to Kubernetes `TokenReview` with the `infernal-law-enrollment`
audience, requires the bound Pod UID, and looks the workload up in an enabled
enrollment binding. Deployed on a real cluster, that path works end to end.

What does not exist is any way to reach step 1. Enrollment needs three rows that
no running component can create:

| Artifact | Table | Production surface |
| --- | --- | --- |
| Identity | `identities` | none |
| Enrollment binding | `service_enrollment_bindings` | none |
| Challenge | `service_enrollment_challenges` | none |

`EnrollmentService::issue_challenge` is implemented and covered by
`tests/enrollment_contract.rs`, but no HTTP route, binary, or CLI calls it —
its only callers are tests. `PostgresEnrollmentBindingRepository::insert_disabled`
has no caller at all. The code comments describe "a kernel operator's own
out-of-band challenge issuance"; that issuance has no implementation. The only
way to bootstrap a cluster today is to write directly to PostgreSQL by hand.

A second problem compounds the first. `ENROLLMENT_CHALLENGE` is read from the
environment at process start, and a challenge is single-use with a 30-second
lifetime (`CHALLENGE_LIFETIME_SECONDS`). A Pod therefore enrolls exactly once
per Deployment revision. When it restarts — OOM kill, node drain, rescheduling,
or a scale-up from one replica to three — the new process re-reads a challenge
that has already been consumed and fails. Enrollment survives one Pod lifetime,
which is not a property a Deployment can rely on.

The instance lease itself is not the problem: `/v1/instances/renew` exists, and
an enrolled instance renews within `MAX_LEASE_SECONDS` (300) from a
`DEFAULT_LEASE_SECONDS` (60) baseline. Only *first* enrollment after a restart
is unrecoverable.

## Decision drivers

- A Deployment must survive Pod restart and horizontal scaling with no human in
  the loop. This is the property the system most visibly lacks today.
- The kernel must not become a database command channel (ADR-0007).
- Enrollment must stay fail-closed: an unbound workload gets nothing.
- Administrative decisions — which workload may act as which service, and what
  it may then do — are human decisions and must remain reviewable and auditable.
- Prefer reusing the existing wire protocol and proof format over redesigning it.

## Considered options

1. **Add an operator CLI that issues challenges.** Smallest change; makes the
   documented workflow real. Does not fix restart or scale-up, because a human
   must act within 30 seconds of each Pod start.
2. **Make challenge issuance self-service, authenticated by the same workload
   token; move identity, binding, and grant administration into a separate
   registrar.**
3. **Drop challenges; authenticate enrollment with `TokenReview` alone.**
   Simplest runtime, but loses replay protection and changes the signed proof
   message, invalidating the existing client contract.
4. **A controller that watches Pods and pre-issues challenges.** Keeps issuance
   kernel-initiated with no protocol change, but races Pod startup against a
   30-second window and reintroduces a component that must track Pod lifecycle.

## Decision

We will take option 2, splitting enrollment along the line that already divides
its security properties.

**What actually authorizes an enrollment today is the workload token and the
binding, not the challenge.** An attacker holding no valid projected token for
the `infernal-law-enrollment` audience fails `TokenReview` regardless of whether
it knows a challenge. An attacker holding one can already enroll, because the
challenge is not secret from the workload it was issued for. The challenge's
real contribution is freshness: it binds a specific ephemeral key to a specific
server-generated value that cannot be replayed.

Accordingly:

**1. The kernel gains `POST /v1/enrollments/challenges`.** The caller presents
its projected ServiceAccount token for the `infernal-law-enrollment` audience
and its claimed Pod UID. The kernel submits the token to `TokenReview`, requires
the audience and bound Pod UID exactly as `authenticate_and_register` already
does, resolves the verified namespace/ServiceAccount/UID through an **enabled**
enrollment binding, and only then generates, stores, and returns a challenge
bound to that stable service ID. No binding, no challenge.

This keeps issuance kernel-initiated and fail-closed — the kernel still
generates the random value and owns its lifetime — while removing the human.
The proof message, the `/v1/enrollments` contract, and `EnrollmentChallenge`
are unchanged; `ENROLLMENT_CHALLENGE` becomes a fallback for kernels not running
this route, not the normal path.

**2. A registrar component owns identities, bindings, and grants.** It is not
reachable through the kernel and holds its own PostgreSQL credentials, so
ADR-0007 is preserved: no caller gains a database command channel through the
mediation boundary. It reconciles declarative desired state — service ID, kind,
display name, the Kubernetes ServiceAccount permitted to become it, and the
grants it should hold — against the database, using constrained procedures in
the style of `create_authority_grant`.

The registrar must **resolve and reconcile ServiceAccount UIDs**, not accept
them as input. `service_enrollment_bindings.service_account_uid` pins a binding
to one specific ServiceAccount object; deleting and recreating that
ServiceAccount changes its UID and silently breaks enrollment while every
manifest still looks correct. A reconciler that watches ServiceAccounts and
updates the bound UID turns a confusing outage into a no-op.

## Consequences

### Positive

- A restarted or newly scheduled Pod enrolls itself. Scaling a Deployment from
  one replica to three produces three enrolled instances with no operator step,
  which is the behavior Kubernetes already assumes.
- The bootstrap becomes reachable in production rather than only from tests.
- Administrative state stays declarative, reviewable, and outside the kernel.
- Recreating a ServiceAccount stops being a silent outage.
- No change to the signed proof or the existing client SDKs.

### Negative

- **A stolen workload token becomes sufficient on its own.** Today an attacker
  with a token also needs an operator to issue a challenge; afterwards it does
  not. This is a real reduction in defense in depth and should be accepted
  deliberately, not by omission. It is bounded by the token's own audience
  restriction, its 600-second expiry, the Pod UID binding, and the requirement
  that an administrator have already enabled a binding for that ServiceAccount.
- The kernel gains a route reachable before any Ed25519 credential exists,
  which must be rate-limited per service ID and per source to prevent challenge
  flooding of `service_enrollment_challenges`.
- The registrar is a new component with direct database access — a second
  privileged writer to the kernel's system of record.

### Follow-up work

- Rate limiting and a bounded retention/expiry sweep for challenge rows.
- Decide whether the registrar is a Kubernetes controller, a CI-invoked job, or
  a CLI; only the ServiceAccount UID reconciliation genuinely needs to run
  continuously.
- Extend the registrar to seed the evaluator identity (ADR-0013), which is
  itself currently unenrollable and causes governed routes to fail closed with
  `403` even after successful authentication.
- Decide whether `ENROLLMENT_CHALLENGE` remains supported or is removed once the
  route exists.

## Implementation

Both halves are built.

- The kernel route is `POST /v1/enrollments/challenges`
  (`EnrollmentService::issue_challenge_for_workload`).
- The registrar is `src/bin/registrar.rs`, deployed by `k8s/registrar/` as a
  Job with its own ServiceAccount and its own database Secret. Its desired
  state is `registrar/services.json`. It is idempotent: a second run reports
  `0 changed`.
- Seeding the sentinel schema versions turned out to be a prerequisite
  (migration `0018`); without those rows every non-artifact governed action
  failed closed with `503`.
- Withdrawing authority needed kernel support that did not exist. Grants were
  strictly append-only, so a grant issued once could never be taken back.
  Migration `0019` adds a single monotonic transition -- `revoked_at` NULL to
  a timestamp -- and keeps rejecting everything else, including un-revoking
  and DELETE. `revoke_authority_grant` is the audited procedure, and
  `matching_grants` now excludes revoked rows.
- Reconciliation prunes only when `REGISTRAR_PRUNE=true`. Withdrawing
  authority is the one direction where a stale or mistaken manifest causes an
  outage rather than an over-permission, so it is never the default and is
  deliberately not enabled on the CronJob.
- `k8s/registrar/cronjob.yaml` reconciles every 15 minutes, which is what
  repairs a ServiceAccount that was deleted and recreated. `registrar/role.sql`
  defines the registrar's own PostgreSQL role: it can write identities and
  bindings, read grants, and execute the three SECURITY DEFINER procedures --
  and cannot read `service_instances`, `authority_decisions`, or write
  `authority_grants` at all.

## Validation

- Deleting an enrolled Pod produces a replacement that reaches a working state
  with no human action and no manifest change.
- Scaling a Deployment to three replicas yields three rows in
  `service_instances`, each with a distinct instance ID and key ID.
- A workload whose binding is disabled receives no challenge and cannot enroll.
- A workload presenting a token for any audience other than
  `infernal-law-enrollment` is refused at issuance.
- Deleting and recreating a ServiceAccount is followed by successful enrollment
  once the registrar has reconciled the new UID. Exercised: recreating
  `infernal-pf2e-rules-simple`'s ServiceAccount broke enrollment into
  CrashLoopBackOff, the CronJob reconciled the new UID, and the Pod recovered
  on its own next restart with no human action.
- A revoked grant stops authorizing immediately, its row survives as history,
  and re-adding it to the manifest issues a fresh grant rather than resurrecting
  the revoked one.
- No manual `INSERT` is required to bring a cluster from empty to serving.

All of the above were exercised on k3s on 2026-09-04. The kernel database was
dropped and recreated empty; the kernel migrated itself (26 tables, 18
migrations, both sentinels), the registrar seeded 8 identities, 5 bindings, 5
admissions and 3 grants, and all seven services then enrolled themselves and
reached ready with zero restarts and no hand-written SQL.
