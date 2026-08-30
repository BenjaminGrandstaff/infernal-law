# infernal-law

Project documentation is under [`docs/`](docs/README.md), including the
[architecture documentation](docs/architecture/README.md).

The required scope of the Rust governance kernel is defined in the
[minimum viable kernel specification](docs/architecture/minimum-viable-kernel.md).

## License and export classification

This project is licensed under the [MIT License](LICENSE).

The project is classified as **EAR99** for U.S. export-control purposes. See
the [export notice](docs/export-control.md) for scope and limitations.

## Development

Run the service locally after starting PostgreSQL and setting its connection
URL:

```sh
export DATABASE_URL='postgres://infernal_law:YOUR_PASSWORD@127.0.0.1:5432/infernal_law'
export INFERNAL_LAW_SERVICE_ID='00000000-0000-4000-8000-000000000001'
cargo run
```

It listens on `0.0.0.0:8080` by default and provides:

- `GET /`
- `GET /health/live`
- `GET /health/ready`
- `GET /v1/kernel-identity` — this process's current public signing key,
  deliberately unauthenticated (see
  [ADR-0014](docs/architecture/decisions/0014-publish-kernel-identity-endpoint.md))
- `POST`/`GET /v1/subscriptions`, `DELETE /v1/subscriptions/{id}` — ILK-010
  subscription create/list/disable, signed and admitted like any other
  governed route. Create and disable additionally require an ILK-002
  authority decision from the evaluator configured by
  `POLICY_EVALUATOR_AUTHORITY` (its host, no scheme or path) and
  `POLICY_EVALUATOR_ID` (its `service_id`, a UUID) — unset or unreachable,
  these routes fail closed with `503` rather than an implicit allow. An
  `allow` additionally requires out-of-band provisioning (an `identities`
  row and enrollment binding per calling service, one for the evaluator,
  and a grant) — see [`NO_ARTIFACT_SCHEMA_VERSION`](src/kernel/authority.rs).
- `POST /v1/authority/schemas` — publishes an ILK-002 schema version
  (`{"kind": "artifact"|"permission_policy", "name": "...", "content_digest":
  "<base64url>"}`) owned by the caller's own verified identity. Publishing
  never activates a schema or grants its publisher permission; a different
  service already owning `name` under that `kind` is rejected as `409`.

Set `BIND_ADDRESS` or `PORT` to change the listener configuration. Startup
fails if `DATABASE_URL` or `INFERNAL_LAW_SERVICE_ID` is absent, the service ID
is not a UUID, PostgreSQL cannot be reached, or the `vector` extension is
unavailable. The readiness endpoint also checks the database connection.
Startup applies the idempotent schema migrations in [`migrations/`](migrations/)
before accepting requests.

The kernel is split into independently testable capability modules. See the
[Rust source layout](docs/architecture/source-layout.md) for targeted test
commands and module ownership.

## Podman

Create a private application network and build the rootless application image:

```sh
podman network create infernal-law
podman build -t localhost/infernal-law:latest .
```

After starting PostgreSQL as described below, run the application:

```sh
podman run --rm --name infernal-law --network infernal-law -p 8080:8080 \
  --env DATABASE_URL='postgres://infernal_law:YOUR_PASSWORD@infernal-law-postgres:5432/infernal_law' \
  --env INFERNAL_LAW_SERVICE_ID='00000000-0000-4000-8000-000000000001' \
  localhost/infernal-law:latest
```

### PostgreSQL with pgvector

Create the local database configuration, changing the example password before
starting the container:

```sh
cp containers/postgres/postgres.env.example \
  containers/postgres/postgres.env
podman build -f containers/postgres/Containerfile \
  -t localhost/infernal-law-postgres:17 .
podman volume create infernal-law-postgres-data
podman run --detach --name infernal-law-postgres \
  --network infernal-law \
  --env-file containers/postgres/postgres.env \
  --publish 127.0.0.1:5432:5432 \
  --volume infernal-law-postgres-data:/var/lib/postgresql/data:Z \
  --health-cmd='pg_isready -U "$POSTGRES_USER" -d "$POSTGRES_DB"' \
  --health-interval=5s --health-timeout=3s --health-retries=10 \
  localhost/infernal-law-postgres:17
```

The initialization script enables the `vector` extension when the persistent
volume is first created. Verify it with:

```sh
podman exec infernal-law-postgres psql \
  --username infernal_law --dbname infernal_law \
  --command="SELECT extname, extversion FROM pg_extension WHERE extname = 'vector';"
```

Stop and restart the database without deleting its volume:

```sh
podman stop infernal-law-postgres
podman start infernal-law-postgres
```

The database port is bound to loopback only. The local environment file and
database volume are intentionally not committed to the repository. Containers
communicate over the private `infernal-law` network; the loopback port exists
for development tools running directly on the host.

## Kubernetes

The base manifests are in [`k8s/base`](k8s/base). Preview or apply them with
Kustomize support built into `kubectl`:

```sh
kubectl kustomize k8s/base
kubectl create secret generic infernal-law-database \
  --from-literal=url='postgres://USER:PASSWORD@DATABASE_HOST:5432/DATABASE_NAME'
kubectl apply -k k8s/base
kubectl port-forward service/infernal-law 8080:80
```

The default image name is `localhost/infernal-law:latest`, suitable for a local
cluster that can access Podman's image store. For a remote cluster, publish the
image to a registry and replace the image name before applying the manifests.
The Deployment expects a Secret named `infernal-law-database` with a `url` key;
the repository does not commit database credentials.
