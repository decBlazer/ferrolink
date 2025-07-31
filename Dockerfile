# syntax=docker/dockerfile:1

###############################
# Stage 1 – Compile static MUSL #
###############################
FROM rust:1.77-slim AS builder

ARG TARGET=x86_64-unknown-linux-musl
ENV CARGO_TERM_COLOR=always

WORKDIR /app

# ---- System deps ----
RUN apt-get update \
    && apt-get install -y --no-install-recommends musl-tools pkg-config libssl-dev ca-certificates \
    && rustup target add "${TARGET}" \
    && rm -rf /var/lib/apt/lists/*

# ---- Layered caching for Rust deps ----
COPY Cargo.toml Cargo.lock ./
COPY shared/Cargo.toml ./shared/Cargo.toml
COPY agent/Cargo.toml ./agent/Cargo.toml

# Empty src to compute dependency graph only
RUN mkdir -p shared/src agent/src \
    && echo "fn main(){}" > agent/src/main.rs \
    && echo "pub fn foo(){}" > shared/src/lib.rs

RUN cargo build --release --target "${TARGET}" -p agent

# ---- Actual source ----
COPY . .
RUN cargo build --release --locked --target "${TARGET}" -p agent \
    && strip target/"${TARGET}"/release/agent

#############################
# Stage 2 – Distroless image #
#############################
FROM gcr.io/distroless/static-debian12:nonroot AS runtime

WORKDIR /app

# Copy binary
COPY --from=builder /app/target/${TARGET}/release/agent /agent

# Upload directory (bind-mount or volume)
VOLUME ["/app/uploads"]

EXPOSE 8443 9090

# Default log level
ENV RUST_LOG=info

ENTRYPOINT ["/agent"]
CMD ["--host","0.0.0.0", "--port","8443", "--metrics-port","9090", "--upload-dir","/app/uploads", "--cert-path","/app/cert.pem", "--key-path","/app/key.pem"] 