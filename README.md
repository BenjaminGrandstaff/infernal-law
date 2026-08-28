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

Run the service locally:

```sh
cargo run
```

It listens on `0.0.0.0:8080` by default and provides:

- `GET /`
- `GET /health/live`
- `GET /health/ready`

Set `BIND_ADDRESS` or `PORT` to change the listener configuration.

The kernel is split into independently testable capability modules. See the
[Rust source layout](docs/architecture/source-layout.md) for targeted test
commands and module ownership.

## Podman

Build and run the rootless container:

```sh
podman build -t localhost/infernal-law:latest .
podman run --rm --name infernal-law -p 8080:8080 \
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
database volume are intentionally not committed to the repository.

## Kubernetes

The base manifests are in [`k8s/base`](k8s/base). Preview or apply them with
Kustomize support built into `kubectl`:

```sh
kubectl kustomize k8s/base
kubectl apply -k k8s/base
kubectl port-forward service/infernal-law 8080:80
```

The default image name is `localhost/infernal-law:latest`, suitable for a local
cluster that can access Podman's image store. For a remote cluster, publish the
image to a registry and replace the image name before applying the manifests.
