# ────────────────────────────── Builder stage ──────────────────────────────
# Rust toolchain ≥1.88 parses Cargo.lock v4
FROM rust:1.88-alpine AS builder            
WORKDIR /app


# Copy the whole workspace in one layer; leverage Cargo’s caching
COPY . .

# add the dev libs that openssl-sys expects
RUN apk add --no-cache musl-dev clang llvm \
                       openssl-dev pkgconf

COPY . .
RUN cargo build --release --locked -p agent \
 && strip target/release/agent

# ────────────────────────────── Runtime stage ──────────────────────────────
FROM alpine:3.20
WORKDIR /app

# Non-root user (optional)
RUN adduser -D -u 1000 ferrolink \
 && mkdir /uploads \
 && chown ferrolink:ferrolink /uploads
USER ferrolink

# binary from builder
COPY --from=builder /app/target/release/agent /usr/local/bin/agent

# mount points for secret certs and uploads
VOLUME /certs
VOLUME /uploads

EXPOSE 8080 9090

# default command uses mounted certs and uploads dir
ENTRYPOINT ["/usr/local/bin/agent"]
CMD ["--host","0.0.0.0","--cert-path","/certs/server.pem","--key-path","/certs/server-key.pem","--upload-dir","/uploads"]