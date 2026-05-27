# ── Build stage ────────────────────────────────────────────────────────────────
# Pinned to Rust 1.87 (matches rust-toolchain.toml).  Do NOT use :latest — it
# changes without warning and can break edition 2024 compatibility.
FROM rust:1.88-slim-bookworm AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config git ca-certificates cmake clang libclang-dev \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock* ./
COPY src/ src/

RUN cargo build --release

# ── Runtime image ──────────────────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/construct-relay /usr/local/bin/construct-relay

VOLUME ["/data"]
EXPOSE 443

ENV RUST_LOG=info

ENTRYPOINT ["construct-relay"]
