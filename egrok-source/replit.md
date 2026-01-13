# egrok - Reverse Tunnel System

A Rust-based reverse tunnel system similar to ngrok that allows exposing local services through a public endpoint.

## Project Overview

This project implements a secure reverse tunnel that bridges internet-facing requests to services running behind firewalls.

### Architecture

```
┌──────────────┐         ┌──────────────────────────────┐         ┌─────────────────┐
│  S3 Client   │         │      Public Server           │         │  Local Server   │
│              │         │   (test.egrok.exaba.io)      │         │  (localhost)    │
└──────┬───────┘         └──────────────┬───────────────┘         └────────┬────────┘
       │                                │                                   │
       │ 1. HTTPS GET /version          │                                   │
       │ ──────────────────────────────>│                                   │
       │              :443              │                                   │
       │                                │                                   │
       │                                │<──── Persistent WebSocket ────────│
       │                                │         (tunnel on :9001)         │
       │                                │                                   │
       │                                │ 2. Forward request over tunnel    │
       │                                │ ─────────────────────────────────>│
       │                                │                                   │
       │                                │ 3. Response over tunnel           │
       │                                │ <─────────────────────────────────│
       │                                │                                   │
       │ 4. HTTPS Response              │                                   │
       │ <──────────────────────────────│                                   │
```

## Components

### 1. egrok-server
The internet-facing server that:
- Listens on port 443 for public HTTPS requests
- Listens on per-customer backhaul ports (9001, 9002, etc.) for tunnel connections
- Routes requests based on subdomain to the correct tunnel
- Manages up to 50 customer tunnels

### 2. egrok (client)
The client that runs behind the firewall:
- Connects outbound to the server's backhaul port
- Authenticates using a token (read from EGROK_TOKEN env var)
- Forwards received requests to a local service
- Sends responses back through the tunnel

### 3. egrok-protocol
Shared library containing:
- Wire protocol (JSON over WebSocket)
- Message types (Auth, HttpRequest, HttpResponse)
- Token hashing utilities (SHA-256)

### 4. example-server
A simple test server with /version endpoint for testing.

## Configuration

### Server Configuration (config.toml)

```toml
[server]
public_port = 443
cert_path = "/etc/letsencrypt/live/egrok.exaba.io/fullchain.pem"
key_path = "/etc/letsencrypt/live/egrok.exaba.io/privkey.pem"
domain = "egrok.exaba.io"

[[customers]]
name = "test"
backhaul_port = 9001
token_hash = "sha256:..."  # Use 'egrok-server hash-token <token>' to generate

[[customers]]
name = "acme"
backhaul_port = 9002
token_hash = "sha256:..."
```

### Generating Token Hashes

```bash
# Generate a random token
TOKEN=$(openssl rand -hex 32)
echo "Token: $TOKEN"

# Hash it for the config file
./target/release/egrok-server hash-token "$TOKEN"
```

### Pre-configured Test Tokens

For testing, these tokens are already configured in config.toml:

| Customer | Port | Token |
|----------|------|-------|
| test | 9001 | `test` |
| acme | 9002 | `acme` |
| demo | 9003 | `hello` |

## Usage

### Running the Server

```bash
# On the public server (egrok.exaba.io)
./target/release/egrok-server run --config config.toml
```

### Running the Client

```bash
# On the machine behind the firewall
export EGROK_TOKEN="your-token-here"
./target/release/egrok --server egrok.exaba.io --port 9001 --local 8080

# For testing with self-signed certs
./target/release/egrok --server egrok.exaba.io --port 9001 --local 8080 --insecure
```

### Running the Example Server

```bash
# Start the local test server
PORT=8080 ./target/release/example-server
```

### Complete Test Scenario

1. **Start the example server locally:**
   ```bash
   PORT=8080 ./target/release/example-server
   ```

2. **Start the egrok client:**
   ```bash
   export EGROK_TOKEN="test"
   ./target/release/egrok --server egrok.exaba.io --port 9001 --local 8080
   ```

3. **Test from anywhere:**
   ```bash
   curl https://test.egrok.exaba.io/version
   ```

## Security

- Tokens are stored as SHA-256 hashes in the server config (never plaintext)
- Client reads token from EGROK_TOKEN environment variable (not CLI args)
- All connections use TLS encryption
- Token verification uses constant-time comparison to prevent timing attacks

## Building

```bash
# Build all components
cargo build --release

# Binaries are in:
# - target/release/egrok-server
# - target/release/egrok
# - target/release/example-server
```

## Project Structure

```
.
├── Cargo.toml              # Workspace manifest
├── config.toml             # Server configuration
├── egrok/                  # Client binary
│   ├── Cargo.toml
│   └── src/main.rs
├── egrok-protocol/         # Shared protocol library
│   ├── Cargo.toml
│   └── src/lib.rs
├── egrok-server/           # Server binary
│   ├── Cargo.toml
│   └── src/main.rs
└── example-server/         # Test server
    ├── Cargo.toml
    └── src/main.rs
```

## Recent Changes

- **Jan 2026**: Initial implementation with full tunnel support
