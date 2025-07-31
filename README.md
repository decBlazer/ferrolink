# FerroLink

A secure, extensible client-server system for remote desktop monitoring and control, built in Rust.

## Architecture

```
┌─────────────────┐       TCP/JSON        ┌───────────────────────┐
│  Laptop Client  │  ◄──────────────────► │  Desktop Agent/Server │
└─────────────────┘                       └───────────────────────┘
    CLI Interface                           Always-on service
```

## Features

- **Real-time System Monitoring**: CPU usage, memory consumption
- **TCP Communication**: JSON-based protocol over TCP
- **Async Performance**: Built with Tokio for concurrent client handling
- **🖥CLI Interface**: Clean command-line interface with clap
- **Structured Logging**: Comprehensive logging with tracing

## Quick Start (TLS-enabled)

### Prerequisites
* Rust 1.70+ with Cargo
* OpenSSL (for generating test certificates)

### Build workspace

```bash
# Build the entire workspace
cargo build --release

# Or build individual components
cargo build -p agent    # Desktop server
cargo build -p client   # Laptop client
cargo build -p shared   # Common library
```

### 1. Generate a self-signed certificate (dev only)
```bash
# Generate key
openssl genrsa -out key.pem 2048
# Generate leaf cert (CA:FALSE) valid for localhost
openssl req -new -x509 -key key.pem -days 365 -out cert.pem \
  -subj "/CN=localhost" \
  -addext "basicConstraints=CA:FALSE" \
  -addext "keyUsage=digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
```

### 2. Run the Agent
```bash
# Listen on 0.0.0.0:8443 with TLS and Prometheus on :9090
RUST_LOG=info \
cargo run -p agent --  \
  --host 0.0.0.0 --port 8443 \
  --cert-path cert.pem --key-path key.pem \
  --upload-dir uploads \
  --metrics-port 9090
```

### 3. Run the Client
```bash
# Ping the agent
RUST_LOG=info \
cargo run -p client --  \
  --host 127.0.0.1 --port 8443 \
  --cert-path cert.pem \
  ping

# Show one-shot metrics
cargo run -p client -- --cert-path cert.pem monitor

# Live TUI (press q to quit)
cargo run -p client -- --cert-path cert.pem tui --interval 1
```

## Command Reference

### Agent Commands
```bash
agent [OPTIONS]

OPTIONS:
    -p, --port <PORT>    Port to listen on [default: 8080]
    -H, --host <HOST>    Host to bind to [default: 127.0.0.1]
    -h, --help           Print help information
```

### Client Commands
```bash
client [OPTIONS] <COMMAND>

Global OPTIONS:
  -H, --host <HOST>       Agent host [default: 127.0.0.1]
  -p, --port <PORT>       Agent port [default: 8443]
      --cert-path <FILE>  Path to server certificate (trust)
      --token <STRING>    Auth token (if required by agent)

COMMANDS:
  ping                     ‑ Test connection
  monitor                  ‑ Fetch current metrics
  watch      [--interval]  ‑ Continuously fetch metrics
  tui        [--interval]  ‑ Terminal dashboard
  send-file  --file <P> [--chunk-size]        ‑ Upload file
  sync       --file <P> [--chunk-size]        ‑ Upload only if hash differs
  exec       --program <P> [-- arg..]         ‑ Remote command execution
  wol        --mac <AA:BB:CC:DD:EE:FF> [--port] ‑ Wake-on-LAN magic packet
```

## Development

### Project Structure
```
ferrolink/
├── shared/          # Common types & protocol
│   ├── src/
│   │   └── lib.rs   # Message types, system metrics
│   └── Cargo.toml
├── agent/           # Desktop server
│   ├── src/
│   │   └── main.rs  # TCP server, system monitoring
│   └── Cargo.toml
├── client/          # Laptop client
│   ├── src/
│   │   └── main.rs  # CLI interface, networking
│   └── Cargo.toml
└── Cargo.toml       # Workspace configuration
```

### Key Technologies
- **Async Runtime**: Tokio for high-performance networking
- **System Info**: sysinfo for cross-platform system metrics
- **CLI**: clap for argument parsing and help generation
- **Logging**: tracing for structured logging
- **Serialization**: serde + serde_json for message protocol

## Roadmap

### Completed
- [x] TLS encryption (server + client trust)
- [x] Authentication token support
- [x] Remote command execution
- [x] File synchronization & chunked uploads
- [x] Wake-on-LAN support
- [x] Terminal UI with ratatui

### Next Up
- [ ] Persist historical metrics & expose Grafana dashboards
- [ ] Binary packaging (cross-compile) & installer scripts
- [ ] Web dashboard (dashboard/ directory)
- [ ] Plugin architecture for custom actions
- [ ] Stress/performance tests

## Usage Examples

### Basic Monitoring
```bash
# Terminal 1: Start agent
./target/release/agent

# Terminal 2: Monitor system
./target/release/client monitor
```

Output:
```
📊 System Metrics (15:42:33)
   CPU Usage: 23.4%
   Memory: 8432 / 16384 MB (51.5%)
```

### Continuous Monitoring
```bash
./target/release/client watch --interval 1
```

Output:
```
🔄 Watching system metrics (Ctrl+C to stop)
──────────────────────────────────────────────────
📊 System Metrics (15:42:33)
   CPU Usage: 23.4%
   Memory: 8432 / 16384 MB (51.5%)
📊 System Metrics (15:42:34)
   CPU Usage: 24.1%
   Memory: 8435 / 16384 MB (51.5%)
```

## Learning Objectives

This project demonstrates:
- **Distributed Systems**: Client-server architecture with async networking
- **Systems Programming**: Low-level system metrics collection
- **Protocol Design**: JSON-based message protocol
- **Error Handling**: Robust error handling with anyhow/thiserror
- **CLI Design**: User-friendly command-line interfaces
- **Async Programming**: Tokio for concurrent request handling
