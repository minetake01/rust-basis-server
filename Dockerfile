# syntax=docker/dockerfile:1

FROM rust:bookworm AS builder
WORKDIR /src

# Copy manifests and source; build the same workspace package used by binary releases.
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY bin ./bin
RUN cargo build --locked --release --package basis-server

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --home-dir /app --create-home --shell /usr/sbin/nologin basis
WORKDIR /app

COPY --from=builder /src/target/release/basis-server-rs /app/basis-server-rs
COPY config /app/config
RUN mkdir -p /app/Logs \
    && chown -R basis:basis /app

ENV RUST_LOG=info
USER basis

# Basis game/network traffic is UDP; health endpoint defaults are configured by the server.
VOLUME ["/app/config", "/app/Logs"]
ENTRYPOINT ["/app/basis-server-rs"]
