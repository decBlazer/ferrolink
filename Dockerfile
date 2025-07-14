# syntax=docker/dockerfile:1

#############################
# Stage 1 – Build the agent #
#############################
FROM rust:1.78-slim AS builder

WORKDIR /app

# --- dependency caching ---------------------------------------------
# Copy manifest files first so Docker cache is invalidated only when
# dependencies change, not on every source edit.
COPY Cargo.toml ./
COPY shared/Cargo.toml ./shared/Cargo.toml
COPY agent/Cargo.toml ./agent/Cargo.toml
COPY client/Cargo.toml ./client/Cargo.toml
# Provide minimal src trees for target discovery
COPY shared/src ./shared/src
COPY agent/src ./agent/src
COPY client/src ./client/src

# Pre-fetch crates
RUN cargo fetch

# Copy the rest (tests, README, etc.) and compile
COPY . .
RUN cargo build --release -p agent --locked

#############################
# Stage 2 – Minimal runtime  #
#############################
FROM debian:bookworm-slim AS runtime

# Install ca-certificates for TLS outbound calls & logging
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the statically linked agent binary from the builder stage
COPY --from=builder /app/target/release/agent /usr/local/bin/agent

# Create default upload directory (can be replaced by a volume)
RUN mkdir /app/uploads
VOLUME ["/app/uploads"]

# Expose the default agent port
EXPOSE 8080

ENV RUST_LOG=info

# Entrypoint & default arguments (override with `docker run ... CMD`)
ENTRYPOINT ["/usr/local/bin/agent"]
CMD ["--host", "0.0.0.0", \
     "--port", "8080", \
     "--upload-dir", "/app/uploads", \
     "--cert-path", "/app/cert.pem", \
     "--key-path", "/app/key.pem"] 