# MetaMesh Plugin: full-hash (Rust)
# High-performance file hashing with multi-algorithm support

FROM rust:1.89-slim-bookworm AS builder
WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

# Copy manifests and build dependencies first (for caching).
# Cargo.lock is copied so the build uses the committed, reproducible
# dependency set instead of re-resolving to the latest crates (which can
# pull in versions requiring a newer Rust edition than this toolchain).
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs && cargo build --release --locked && rm -rf src

# Copy source and build
COPY src/ ./src/
RUN touch src/main.rs && cargo build --release --locked

FROM debian:bookworm-slim
WORKDIR /app

# Install runtime dependencies (curl for healthcheck, ca-certificates for HTTPS)
RUN apt-get update && apt-get install -y ca-certificates curl && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/metamesh-plugin-fast-full-hash /app/plugin

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8080/health || exit 1

ENV RUST_LOG=info
ENV CACHE_PATH=/cache

# WebDAV URL for file access (set by container manager)
# Example: http://meta-sort-dev/webdav
ENV WEBDAV_URL=

CMD ["/app/plugin"]
