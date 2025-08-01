# ─────────────────────────────── 0.  Common base image tag ────────────────
ARG RUST_TAG=1.88-alpine           # one place to bump the tool-chain

# ─────────────────────────────── 1.  Planner (cargo-chef) ────────────────
FROM rust:${RUST_TAG} AS planner
RUN apk add --no-cache musl-dev clang llvm openssl-dev pkgconf
RUN cargo install cargo-chef
WORKDIR /app

# Only copy manifest files so dependency build can be cached
COPY Cargo.toml Cargo.lock ./
COPY agent/Cargo.toml ./agent/
COPY shared/Cargo.toml ./shared/
COPY client/Cargo.toml ./client/

# Compute dependency graph
RUN cargo chef prepare --recipe-path recipe.json

# ─────────────────────────────── 2.  Builder (deps + app) ────────────────
FROM rust:${RUST_TAG} AS builder
RUN apk add --no-cache musl-dev clang llvm openssl-dev pkgconf
WORKDIR /app

# Re-use the cached dependency layer
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --recipe-path recipe.json

# Now copy the full workspace and compile only changed crates
COPY . .
RUN cargo build --release --locked -p agent && \
    strip target/release/agent

# ─────────────────────────────── 3.  Runtime  ────────────────────────────
FROM alpine:3.20
WORKDIR /app

# Non-root user and writable uploads dir
RUN adduser -D -u 1000 ferrolink \
 && mkdir /uploads \
 && chown ferrolink:ferrolink /uploads
USER ferrolink

# Binary
COPY --from=builder /app/target/release/agent /usr/local/bin/agent

# Mount points for secrets and uploaded files
VOLUME /certs
VOLUME /uploads

EXPOSE 8080 9090
ENTRYPOINT ["/usr/local/bin/agent"]
CMD ["--host","0.0.0.0", "--cert-path","/certs/server.pem", "--key-path","/certs/server-key.pem", "--upload-dir","/uploads"]