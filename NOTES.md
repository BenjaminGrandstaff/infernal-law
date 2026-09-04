# Reconstruction Notes

_Started 2026-09-04._

## Context

This stack is being reconstructed on a new system. The previous working tree is
gone, so everything below is derived from what is committed here — not from a
running install. Treat the repositories as the source of truth and assume no
host-local state survives.

The four services that carry a PostgreSQL database are:

| Service | Migrations | Notes |
| --- | --- | --- |
| `infernal-law` | 17 | the governance kernel; requires `pgvector` |
| `infernal-librarian-simple` | 2 | documents + search |
| `infernal-pf2e-rules-simple` | 2 | rules store |
| `infernal-pf2e-parser-simple` | 1 | parser output |

All four use `r2d2` + `r2d2_postgres` (a **blocking** pool), a `migrations/`
directory of zero-padded SQL, and per-service database isolation — separate
role, database, and container hostname each:

```
postgres://infernal_law:…@infernal-law-postgres:5432/infernal_law
postgres://infernal_librarian:…@infernal-librarian-postgres:5432/infernal_librarian
```

The remaining repositories (`worker`, `taskmaster`, `inquisitor`, and the five
client SDKs) hold no database and reach these over HTTP.

## Goal: make the install self-healing

The intent is for a service to bring itself to a correct state on start rather
than depending on a host that was hand-prepared once and never reproduced. Some
of that property already exists here and is worth keeping deliberately:

- **Schema ships inside the binary.** `Database::migrate()` concatenates all 17
  migrations through `include_str!` and applies them in a single
  `batch_execute`; `wiring.rs` calls it during startup. There is no external
  migration runner and no separate deploy step to forget.
- **Every migration is re-runnable.** All DDL is `CREATE TABLE / INDEX IF NOT
  EXISTS`, and `0012` rebuilds its index with `DROP INDEX IF EXISTS` first. The
  full batch therefore executes on every boot without error.
- **Missing prerequisites fail closed.** `require_vector_extension()` aborts
  startup with `VectorExtensionMissing` rather than serving a half-working
  kernel.
- **Applied migrations are recorded.** `kernel_schema_migrations` (created in
  `0001_identities.sql`) holds a `version`/`name`/`applied_at` row per migration,
  and each file self-registers with `INSERT ... ON CONFLICT (version) DO
  NOTHING`. A fresh boot lands all 17.

Note what that table does *not* do: `migrate()` never reads it. It is an
inventory of what has been applied, not a gate on what to apply — the entire
batch replays at every start regardless. Idempotency is therefore load-bearing
rather than incidental, and any future migration not written to be re-runnable
will break startup on an existing database, not just on a fresh one. This
constraint should be stated wherever migrations are added.

## Blocker: move and stabilize the install first

Before building anything new on top, the install needs to be reproducible on
this machine:

1. **`pgvector` is a hard dependency of `infernal-law`.** Stock PostgreSQL does
   not ship it, and the kernel refuses to start without it.
   `containers/postgres/` builds an image that runs
   `init/001-enable-vector.sql`; a hand-installed system PostgreSQL will need
   the extension added separately. This is the most likely first failure on a
   new host.
2. **Four databases, four roles, four sets of credentials** must exist before
   any service starts. Nothing in the repositories provisions them.
3. **`infernal-law` depends on `infernal-client-rs` as a git dependency pinned
   to a rev** (`be3244a`). Reconstruction needs network access to GitHub, and
   bumping the client is an explicit rev change here.
4. **Out-of-band provisioning is required for the governed routes** — an
   `identities` row and enrollment binding per calling service, one for the
   evaluator, and a grant. With `POLICY_EVALUATOR_*` unset or unreachable,
   those routes fail closed with `503`. A schema that migrated cleanly is
   therefore not the same thing as a working install.

Only once a clean host reaches a running, provisioned state reproducibly does it
make sense to add self-healing behavior on top — otherwise the healing logic
cannot be distinguished from the setup it is meant to repair.

## Known rough edge

The migration list in `src/infrastructure/database.rs` is maintained by hand:
adding a file to `migrations/` does nothing until its `include_str!` line is
added too. On-disk and wired-in counts currently agree at 17, but they can drift
silently, and the failure mode is a missing table at runtime rather than a build
error.

## Verified reconstruction (2026-09-04)

The stack was rebuilt from these repositories on a clean Fedora 44 host. What
was actually needed:

- **Rust 1.98.0** (Fedora packaged) — satisfies `rust-version = "1.85"` and
  edition 2024. `cargo build` succeeded with no additional system libraries;
  `reqwest` uses `rustls-tls`, so there is no OpenSSL dev dependency.
- **PostgreSQL 18.6** plus the **`pgvector` 0.8.0** package. `CREATE EXTENSION
  vector` must be run once per database — installing the RPM alone is not
  enough, and `require_vector_extension()` will refuse to start without it.
- **`pg_hba.conf` needs editing.** Fedora's default is `ident` for
  `127.0.0.1/32`, which a `postgres://user:pass@127.0.0.1` URL cannot satisfy.
  Change the two `host all all` lines to `scram-sha-256` and reload.
- One role and one database per service, owned by that role.

With that in place `./target/debug/infernal-law` came up in about a second,
applied all 17 migrations itself into an empty database (26 tables), and served
`/`, `/health/live`, `/health/ready` and `/v1/kernel-identity` with `200`.

This confirms the schema half of the install is genuinely self-healing against
an empty database. The identity/grant provisioning described above is not — the
governed routes still require out-of-band setup before they do anything.
