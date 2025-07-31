# syntax=docker/dockerfile:1

###############################
# Stage 1 – Compile static MUSL #
###############################
FROM rust:1.77-slim AS builder

# Target defaults to host glibc (x86_64-unknown-linux-gnu)
ARG CARGO_TERM_COLOR=always

WORKDIR /app

# ---- System deps ----
RUN apt-get update \
    && apt-get install -y --no-install-recommends pkg-config libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# ---- Layered caching for Rust deps ----
COPY Cargo.toml Cargo.lock ./
COPY shared/Cargo.toml ./shared/Cargo.toml
COPY agent/Cargo.toml ./agent/Cargo.toml
COPY client/Cargo.toml ./client/Cargo.toml

# Copy full workspace & build
COPY . .
RUN cargo build --release --locked -p agent \
    && strip target/release/agent

#############################
# Stage 2 – Distroless image #
#############################
FROM gcr.io/distroless/cc-debian12:nonroot AS runtime

# Target defaults to host glibc (x86_64-unknown-linux-gnu)
ARG CARGO_TERM_COLOR=always

WORKDIR /app

# Copy binary
COPY --from=builder /app/target/release/agent /agent

# Upload directory (bind-mount or volume)
VOLUME ["/app/uploads"]

EXPOSE 8443 9090

# Default log level
ENV RUST_LOG=info

ENTRYPOINT ["/agent"]
CMD ["--host","0.0.0.0", "--port","8443", "--metrics-port","9090", "--upload-dir","/app/uploads", "--cert-path","/app/cert.pem", "--key-path","/app/key.pem"] 