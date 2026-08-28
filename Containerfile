FROM docker.io/library/rust:1.85-bookworm AS builder

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --locked --release

FROM docker.io/library/debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install --no-install-recommends --yes ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/target/release/infernal-law /usr/local/bin/infernal-law

ENV BIND_ADDRESS=0.0.0.0 \
    PORT=8080
EXPOSE 8080
USER 65532:65532

ENTRYPOINT ["/usr/local/bin/infernal-law"]
