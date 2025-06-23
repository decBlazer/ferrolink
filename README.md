# 🔧 FerroLink

A secure, extensible client-server system for remote desktop monitoring and control, built in Rust.

## 🏗️ Architecture

```
┌─────────────────┐       TCP/JSON        ┌───────────────────────┐
│  Laptop Client  │  ◄──────────────────► │  Desktop Agent/Server │
└─────────────────┘                       └───────────────────────┘
    CLI Interface                           Always-on service
```

## ✨ Features (Phase 1 - MVP)

- **📊 Real-time System Monitoring**: CPU usage, memory consumption
- **🔗 TCP Communication**: JSON-based protocol over TCP
- **⚡ Async Performance**: Built with Tokio for concurrent client handling
- **🖥️ CLI Interface**: Clean command-line interface with clap
- **📝 Structured Logging**: Comprehensive logging with tracing

## 🚀 Quick Start

### Prerequisites
- Rust 1.70+ with Cargo

### Building

```bash
# Build the entire workspace
cargo build --release

# Or build individual components
cargo build -p agent    # Desktop server
cargo build -p client   # Laptop client
cargo build -p shared   # Common library
```

### Running

#### 1. Start the Agent (Desktop)
```bash
# Default: listen on 127.0.0.1:8080
./target/release/agent

# Custom host/port
./target/release/agent --host 0.0.0.0 --port 9000
```

#### 2. Connect with Client (Laptop)
```bash
# Test connection
./target/release/client ping

# Get current system metrics
./target/release/client monitor

# Watch metrics continuously (updates every 2 seconds)
./target/release/client watch

# Watch with custom interval
./target/release/client watch --interval 5

# Connect to remote host
./target/release/client --host 192.168.1.100 monitor
```

## 📋 Command Reference

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

OPTIONS:
    -H, --host <HOST>    Agent host [default: 127.0.0.1]
    -p, --port <PORT>    Agent port [default: 8080]

COMMANDS:
    ping      Test connection to the agent
    monitor   Get current system metrics
    watch     Monitor system metrics continuously
```

## 🔧 Development

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

## 🎯 Roadmap

### Phase 2: Advanced Features
- [ ] Remote command execution
- [ ] File synchronization
- [ ] Wake-on-LAN support
- [ ] Terminal UI with ratatui

### Phase 3: Production Ready
- [ ] TLS encryption
- [ ] Authentication system
- [ ] Plugin architecture
- [ ] Performance dashboard

## 🤝 Usage Examples

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

## 🎓 Learning Objectives

This project demonstrates:
- **Distributed Systems**: Client-server architecture with async networking
- **Systems Programming**: Low-level system metrics collection
- **Protocol Design**: JSON-based message protocol
- **Error Handling**: Robust error handling with anyhow/thiserror
- **CLI Design**: User-friendly command-line interfaces
- **Async Programming**: Tokio for concurrent request handling

Perfect for showcasing skills for software engineering internships!
