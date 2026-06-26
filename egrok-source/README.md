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

## Dissertation verification tests

These tests confirm the egrok tunnel works correctly end-to-end. Run them from the Mac with the relay server running and the Android app connected (both tunnels authenticated).

**Prerequisites:**
- `cargo run --release --bin egrok-server -- run --config local-config.toml` running in one terminal
- Android app: test servers started, egrok tunnel started, USB connected with `adb reverse` set up
- `/etc/hosts` contains `127.0.0.1 s3.localhost`
- For direct-bypass comparisons, also forward the test server port from Mac to phone:
  ```bash
  adb -s <device-id> forward tcp:9001 tcp:9001
  ```
  (`adb reverse` goes phone→Mac for backhaul; `adb forward` goes Mac→phone for direct access)

---

### Test 1 — Data integrity (checksum)

Fetches a payload through the tunnel and verifies its SHA-256 hash matches the direct value.

```bash
# Through tunnel
curl -sk https://mgmt.localhost:8443/test | sha256sum

# Direct to phone (bypasses tunnel — for comparison)
curl -s http://localhost:9001/test | sha256sum
```

Both hashes must match. Expected: `23ee2e82093d4de2ceb06b045c2599bff44e5d04294ee60888edeba2d800841b`

---

### Test 2 — Concurrent requests (no cross-contamination)

Sends 10 simultaneous requests and checks every response has the same hash.

```bash
for i in $(seq 1 10); do curl -sk https://mgmt.localhost:8443/test | sha256sum & done; wait
```

All 10 lines must print the same hash. Any mismatch indicates response cross-contamination.

---

### Test 3 — Latency overhead

Measures round-trip time through the tunnel vs direct.

```bash
# Tunnel latency
curl -sk -w "Tunnel: %{time_total}s\n" -o /dev/null https://mgmt.localhost:8443/test

# Direct latency
curl -s -w "Direct: %{time_total}s\n" -o /dev/null http://localhost:9001/test
```

Overhead (tunnel − direct) must be ≤ 10ms to meet the dissertation requirement.

---

### Test 4 — Auth rejection

Verifies the server rejects requests with a wrong token. The tunnel connection itself uses the correct token; this test bypasses the tunnel and hits the backhaul port directly with a bad token.

```bash
# Should fail with a non-200 response or connection reset
curl -sk https://mgmt.localhost:8443/test -H "X-Egrok-Token: wrongtoken"
```

Expected: connection refused or HTTP error (not a valid payload).

---

### Quick all-in-one run

Copy-paste this block to run tests 1–3 and print a summary:

```bash
echo "=== EGROK VERIFICATION ==="

echo ""
echo "--- Test 1: Integrity ---"
HASH=$(curl -sk https://mgmt.localhost:8443/test | sha256sum | awk '{print $1}')
EXPECTED="23ee2e82093d4de2ceb06b045c2599bff44e5d04294ee60888edeba2d800841b"
[ "$HASH" = "$EXPECTED" ] && echo "PASS  $HASH" || echo "FAIL  got: $HASH"

echo ""
echo "--- Test 2: Concurrency (10 simultaneous) ---"
RESULTS=$(for i in $(seq 1 10); do curl -sk https://mgmt.localhost:8443/test | sha256sum & done; wait)
echo "$RESULTS"
MISMATCHES=$(echo "$RESULTS" | sort -u | wc -l | tr -d ' ')
[ "$MISMATCHES" -eq 1 ] && echo "PASS  all identical" || echo "FAIL  $MISMATCHES distinct hashes"

echo ""
echo "--- Test 3: Latency ---"
T_TUNNEL=$(curl -sk -w "%{time_total}" -o /dev/null https://mgmt.localhost:8443/test)
T_DIRECT=$(curl -s  -w "%{time_total}" -o /dev/null http://localhost:9001/test)
echo "Tunnel: $(echo "$T_TUNNEL * 1000" | bc)ms"
echo "Direct: $(echo "$T_DIRECT * 1000" | bc)ms"
OVERHEAD=$(echo "($T_TUNNEL - $T_DIRECT) * 1000" | bc)
echo "Overhead: ${OVERHEAD}ms"
PASS=$(echo "$OVERHEAD < 10" | bc)
[ "$PASS" -eq 1 ] && echo "PASS  overhead < 10ms" || echo "FAIL  overhead >= 10ms"

echo ""
echo "==========================="
```
