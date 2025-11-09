# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Project Overview

plan1 is a P2P heterogeneous cluster application written in Rust that implements HTTPS with bidirectional Trust-On-First-Use (TOFU) certificate handling. This is a peer-to-peer system where each node acts as both server and client, establishing mutual trust through self-signed certificates.

## Common Commands

### Build and Run
```powershell
# Build the project
cargo build

# Run the main server (listens on port 39001)
cargo run

# Build in release mode
cargo build --release
```

### Testing
```powershell
# Run all tests
cargo test

# Test locally with curl (HTTP auto-redirects to HTTPS)
curl http://localhost:39001/test

# Test direct HTTPS (requires -k to ignore self-signed cert)
curl -k https://localhost:39001/test
```

### Code Quality
```powershell
# Check code without building
cargo check

# Format code
cargo fmt

# Run linter
cargo clippy
```

### Running Additional Binaries
```powershell
# Run peer client
cargo run --bin peer

# Run test client
cargo run --bin test_client
```

## Architecture

### Core Concept: Bidirectional TOFU
The application implements Trust-On-First-Use (TOFU) with bidirectional trust negotiation:

1. **Server receives connection** → Extracts client IP from TLS handshake
2. **Automatic reverse connection** → Server connects back to the peer
3. **Mutual certificate exchange** → Both peers verify and store each other's certificates
4. **Trust established** → Future connections verified against stored fingerprints

### Module Structure

- **`cert_manager`**: Auto-generates and manages self-signed ECDSA P-256 certificates
  - Certificates stored in `certs/server_cert.pem` and `certs/server_key.pem`
  - Generates on first run, reuses on subsequent runs
  
- **`peer_trust`**: Manages trusted peer database
  - Stores certificate fingerprints in `certs/trusted_peers.json`
  - Tracks first_seen and last_seen timestamps
  - Detects certificate changes (potential MITM)

- **`peer_client`**: Client for connecting to other peers
  - Uses custom certificate verifier for TOFU
  - Automatically trusts new peer certificates
  - Verifies known peers against stored fingerprints

- **`cert_verifier`**: Custom rustls ServerCertVerifier implementation
  - Accepts self-signed certificates
  - Implements TOFU logic for peer verification

- **`main.rs`**: HTTPS server implementation
  - Listens on port 39001
  - Detects HTTP vs HTTPS and auto-redirects HTTP → HTTPS
  - Initiates reverse connections for bidirectional trust
  - Supports `X-Peer-Port` header for peers on non-standard ports

### Binary Targets

- **`plan1` (main)**: The primary HTTPS server
- **`peer`**: Peer client binary (in `src/bin/peer.rs`)
- **`test_client`**: Test client utility (in `src/bin/test_client.rs`)

## Key Implementation Details

### HTTP-to-HTTPS Auto-Redirect
The server peeks at incoming connections to detect plain HTTP requests (starting with `GET`, `POST`, etc.) versus TLS handshakes (starting with `0x16`). Plain HTTP requests receive a 301 redirect to HTTPS.

### Port Detection with X-Peer-Port Header
Peers can specify which port their server is listening on via the `X-Peer-Port` HTTP header. This is important when:
- Running multiple peers on the same machine (different ports)
- Peers behind NAT/port forwarding
- Default: 39001

### Certificate Pinning
Once a peer's certificate is trusted, its SHA-256 fingerprint is stored. Any subsequent connection attempt with a different certificate triggers a warning and is rejected.

### TOFU Security Model
- ✅ **Protects against**: MITM attacks after first connection
- ⚠️ **Vulnerable to**: MITM on first connection (same as SSH)
- ✅ **Suitable for**: Lab environments, internal networks, P2P applications
- ⚠️ **Production use**: Requires out-of-band fingerprint verification

## Development Notes

### Windows-Specific Build Configuration
The project uses MinGW for Windows compilation (see `.cargo/config.toml`). This is already configured.

### Async Runtime
Uses Tokio for async operations. All I/O is asynchronous using `tokio::io` traits.

### TLS Library
Uses `rustls` (not OpenSSL) with:
- `rustls` 0.20.0 with `dangerous_configuration` feature (enables custom cert verification)
- `tokio-rustls` 0.23 for Tokio integration

### Certificate Generation
Uses `rcgen` 0.10 for self-signed certificate generation. Certificates are ECDSA P-256 with 1-year validity.

## Troubleshooting

### Browser shows "Certificate Unknown" or "Insecure Connection"
**Expected behavior.** Self-signed certificates are not trusted by browsers. Either:
- Accept the security warning in browser
- Use `curl -k` for testing
- Use the Rust peer client which implements TOFU

### "TLS handshake failed: CorruptMessage"
This occurs when sending plain HTTP to the HTTPS server. The server now detects this and auto-redirects, but older documentation may reference this error.

### Certificate Mismatch Warning
If a peer's certificate changes, the connection will be rejected with:
```
⚠ WARNING: Certificate changed for peer 192.168.1.100:39001!
  Expected: <old_fingerprint>
  Received: <new_fingerprint>
```
**Possible causes**: Peer regenerated certificate, MITM attack, or different node at same address.
**Resolution**: Verify with peer operator, then remove old entry from `certs/trusted_peers.json`

### Reverse Connection Fails
If the server logs "⚠ Reverse connection failed", this is normal when:
- Client is a browser (not running a peer server)
- Client is behind NAT without port forwarding
- Client is on a different port (use `X-Peer-Port` header)

## Documentation Files

The repository includes extensive documentation:
- **QUICKSTART.md**: Quick start guide for running the server
- **TOFU_README.md**: Detailed TOFU architecture and security model
- **BIDIRECTIONAL_TRUST.md**: How mutual trust negotiation works
- **IMPLEMENTATION_SUMMARY.md**: Complete implementation details and architecture
- **CERT_EXCHANGE_TROUBLESHOOTING.md**: Troubleshooting certificate issues
- **PEER_PORT_HEADER.md**: Using `X-Peer-Port` header for non-standard ports
- **HTTP_REDIRECT.md** & **HTTP_REDIRECT_SUMMARY.md**: HTTP-to-HTTPS redirect details
- **LOGGING_GUIDE.md**: Logging implementation details

## Project Roadmap

Current status: ✅ HTTPS with Bidirectional TOFU complete

Future features (see README.md):
- Config file reading
- Internal database connection
- Time keeping and synchronization
- Message types (join, status, time)
- Database objects (peers, tasks, telemetry)

## Code Style

When working with this codebase:
- Use descriptive logging with prefixes: `[CONN]`, `[TLS]`, `[HTTP]`, `[PEER]`, `[CLIENT]`, `[ERROR]`
- Async functions use Tokio's async/await
- Error handling uses `Result<T, Box<dyn std::error::Error>>`
- Print statements for user-facing output (no logging framework yet)
- Use `println!` with emojis for status: ✓ for success, ✗ for failure, ⚠ for warnings
