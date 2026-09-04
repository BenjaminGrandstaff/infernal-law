FROM docker.io/library/rust:1.85-bookworm AS builder

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY migrations ./migrations
RUN cargo build --locked --release

FROM docker.io/library/debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install --no-install-recommends --yes ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/target/release/infernal-law /usr/local/bin/infernal-law
# The registrar (ADR-0015) ships in the same image but is never started by
# the kernel's entrypoint: it runs as its own Job, with its own database
# credential, so no SQL surface is added to the kernel itself.
COPY --from=builder /src/target/release/registrar /usr/local/bin/infernal-registrar

ENV BIND_ADDRESS=0.0.0.0 \
    PORT=8080
EXPOSE 8080
USER 65532:65532

ENTRYPOINT ["/usr/local/bin/infernal-law"]
