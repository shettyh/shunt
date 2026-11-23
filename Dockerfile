# syntax=docker/dockerfile:1.7

FROM rust:1-bookworm AS builder

ARG TARGETARCH

WORKDIR /src

# Copy manifests first to maximize Docker layer caching.
COPY Cargo.toml Cargo.lock ./
COPY crates/shunt-plugin-sdk/Cargo.toml crates/shunt-plugin-sdk/Cargo.toml
COPY crates/shunt-core/Cargo.toml crates/shunt-core/Cargo.toml
COPY crates/shunt-plugins/Cargo.toml crates/shunt-plugins/Cargo.toml
COPY crates/shunt-ai/Cargo.toml crates/shunt-ai/Cargo.toml
COPY crates/shunt-mcp/Cargo.toml crates/shunt-mcp/Cargo.toml
COPY crates/shunt-config/Cargo.toml crates/shunt-config/Cargo.toml
COPY crates/shunt-test/Cargo.toml crates/shunt-test/Cargo.toml
COPY crates/shunt-cli/Cargo.toml crates/shunt-cli/Cargo.toml
COPY benches/shunt-bench/Cargo.toml benches/shunt-bench/Cargo.toml

# Copy workspace sources.
COPY crates ./crates
COPY benches ./benches

RUN --mount=type=cache,id=cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=cargo-git,target=/usr/local/cargo/git \
    --mount=type=cache,id=cargo-target-${TARGETARCH},target=/src/target \
    cargo build --release --locked -p shunt-cli --bin shunt && \
    cp /src/target/release/shunt /usr/local/bin/shunt

FROM gcr.io/distroless/cc-debian12:nonroot

LABEL org.opencontainers.image.title="shunt" \
      org.opencontainers.image.description="Ultra-lean, pluggable Rust HTTP & AI gateway" \
      org.opencontainers.image.source="https://github.com/shettyh/shunt" \
      org.opencontainers.image.licenses="Apache-2.0"

COPY --from=builder /usr/local/bin/shunt /usr/local/bin/shunt
COPY examples/shunt.toml /etc/shunt/shunt.toml

EXPOSE 8080 9090

ENTRYPOINT ["/usr/local/bin/shunt"]
CMD ["run", "-c", "/etc/shunt/shunt.toml"]
