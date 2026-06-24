# egrok

Self-hosted reverse proxy tunnel (ngrok replacement) written in Rust. Exposes services running on a private device (e.g. an Android phone) to a network via a relay server.

## Requirements

- Rust toolchain (`rustup` + `cargo`)
- [`cargo-ndk`](https://github.com/bbqsrc/cargo-ndk) for building the Android JNI library:
  ```
  cargo install cargo-ndk
  ```
- Android NDK installed and `ANDROID_NDK_HOME` set (via Android Studio SDK Manager)
- OpenSSL (`brew install openssl` on macOS) for generating local TLS certs

## Project structure

| Crate | Purpose |
|---|---|
| `egrok-protocol` | Shared WebSocket message types |
| `egrok-server` | Relay server (runs on Mac/VPS) |
| `egrok` | CLI tunnel client |
| `egrokshim` | Android JNI bridge (`libegrokshim.so`) |

## Local dev setup

### 1. Generate a self-signed cert

```bash
openssl req -x509 -newkey rsa:4096 -keyout local.key -out local.crt -days 365 -nodes -subj "/CN=localhost"
```

### 2. Run the relay server

```bash
cargo run --release --bin egrok-server -- run --config local-config.toml
```

Server listens on:
- `8443` — public HTTPS (TLS-terminated, routes by subdomain)
- `7001` — S3 backhaul (phone connects here)
- `7002` — management backhaul (phone connects here)

Default token for local dev: `test` (SHA-256: `9f86d081...`)

### 3. Build the Android `.so`

```bash
cargo ndk -t arm64-v8a -o ../../android-app/app/src/main/jniLibs build --release -p egrokshim
```

### 4. Connect the phone (USB)

```bash
adb -s <device-id> reverse tcp:7001 tcp:7001
adb -s <device-id> reverse tcp:7002 tcp:7002
```

Then rebuild and run the Android app. Both tunnels will connect through USB instead of WiFi (required because most routers block device-to-device WiFi traffic).

### 5. S3 access from Mac

Add to `/etc/hosts`:
```
127.0.0.1 s3.localhost
```

Then use any S3 client pointed at `https://s3.localhost:8443` with `--no-verify-ssl`.

## Token hashing

To use a different token, hash it and update `local-config.toml`:

```bash
cargo run --release --bin egrok-server -- hash-token <yourtoken>
```
