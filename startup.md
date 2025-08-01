# FerroLink – Quick Start Guide

This doc walks you from a clean machine to a running **FerroLink** stack (Agent + Prometheus + Dashboard) and a local Client that can talk to it.

---
## 0. Prerequisites

* **Rust** ≥ 1.70 (rustup recommended)
* **Docker** + **docker-compose**
* **OpenSSL CLI** – only for generating dev certificates

> On Ubuntu:
> ```bash
> sudo apt update && sudo apt install -y build-essential pkg-config libssl-dev \
>     docker.io docker-compose openssl
> curl https://sh.rustup.rs -sSf | sh            # installs Rust
> ```

---
## 1. Clone & build

```bash
# 1.1 clone
 git clone https://github.com/<you>/ferrolink.git
 cd ferrolink

# 1.2 (optional) build everything once – improves IDE experience
 cargo build --workspace --release
```

---
## 2. TLS certificates (development setup)

Rustls requires a proper chain: **CA → server leaf**. Copy-paste below to generate fresh dev certs that satisfy that requirement.

```bash
# 2.1  Create a local CA (valid 10 years)
openssl genrsa -out ca-key.pem 4096
openssl req -x509 -new -key ca-key.pem -sha256 -days 3650 \
    -out ca-cert.pem -subj "/CN=FerroLink Dev CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"

# 2.2  Create server key + CSR
openssl genrsa -out server-key.pem 2048
openssl req -new -key server-key.pem -out server.csr \
    -subj "/CN=localhost"    # adjust if you expose on another hostname

# 2.3  Sign the CSR – CA:FALSE, SAN localhost + 127.0.0.1
cat > server-ext.cnf <<'EOF'
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt
[alt]
DNS.1 = localhost
IP.1  = 127.0.0.1
EOF

openssl x509 -req -in server.csr -CA ca-cert.pem -CAkey ca-key.pem \
    -CAcreateserial -out server.pem -days 365 -sha256 -extfile server-ext.cnf
```

Files produced:

* `server.pem`, `server-key.pem` → used by **Agent**
* `ca-cert.pem`                  → trusted by **Client**

---
## 3. Environment variables

Create a `.env` file (used by docker-compose) – example:

```env
# PostgreSQL (migrations + Agent logs)
POSTGRES_USER=ferrolink
POSTGRES_PASSWORD=ferropass
POSTGRES_DB=ferrolink
DATABASE_URL=postgres://ferrolink:ferropass@postgres:5432/ferrolink

# optional: authentication
# FERROLINK_TOKEN=my-super-secret-token
```

---
## 4. Start the stack with Docker Compose

```bash
# 4.1  Wire certs into compose
# (they are already referenced, we just need the files)

# 4.2  Launch services (Agent, Postgres, Prometheus, Dashboard)
docker compose up -d --build

# 4.3  Follow the Agent logs – should end with “Agent listening …”
docker logs -f ferrolink-agent
```

Stack overview (all ports are configurable in `docker-compose.yml`):

* **Agent** – 0.0.0.0:8080 (TLS) + 9090 (/metrics)
* **PostgreSQL** – 5432
* **Prometheus** – 9091 (scrapes 9090)
* **Dashboard** – 3000 (static site from `dashboard/`)

---
## 5. Build & use the Client

```bash
# 5.1  build
cargo build -p client --release
# or run directly via cargo run …

# 5.2  Quick smoke tests (use lowercase sub-commands; global flags first)

# Ping
cargo run -p client -- --host 127.0.0.1 --cert-path ca-cert.pem ping

# Fetch one-shot system metrics
cargo run -p client -- --cert-path ca-cert.pem monitor

# Execute a command on the remote machine
cargo run -p client -- --cert-path ca-cert.pem exec ls -- -l /tmp

# Watch metrics continuously every 2 s
cargo run -p client -- --cert-path ca-cert.pem watch --interval 2

# Fancy terminal UI (quit with q)
cargo run -p client -- --cert-path ca-cert.pem tui
```

> **Tip:** If you set `FERROLINK_TOKEN` in `.env`, add `--token YOUR_TOKEN` to every client command.

---
## 6. Prometheus & Dashboard

* Prometheus UI → <http://localhost:9091>
* `/metrics` endpoint exported by Agent → <https://localhost:9090/metrics>
* Static dashboard (if you built it) → <http://localhost:3000>

---
## 7. Common maintenance

```bash
# Restart services after code changes
docker compose up -d --build agent         # just rebuild Agent layer

# Tear everything down
docker compose down -v                     # -v drops volumes (database!)

# Connect to Postgres
psql postgres://ferrolink:ferropass@localhost:5432/ferrolink
```

---
Happy hacking & contributions welcome!   