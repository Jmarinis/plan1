# Bidirectional Trust Negotiation

## Overview

Your P2P application now implements **bidirectional trust negotiation**. When a peer receives a connection, it automatically initiates a reverse connection to establish mutual trust.

## How It Works

### Connection Flow

```
Peer A (192.168.1.100)          Peer B (192.168.1.200)
        |                                |
        |  1. Connect to B:39001         |
        |------------------------------->|
        |                                |
        |  2. TLS Handshake (A's cert)   |
        |<-------------------------------|
        |                                |
        |    3. B initiates reverse      |
        |       connection to A:39001    |
        |<-------------------------------|
        |                                |
        |  4. TLS Handshake (B's cert)   |
        |------------------------------->|
        |                                |
        |  5. Both peers now trust each  |
        |     other's certificates       |
```

### Step-by-Step Process

1. **Peer A connects to Peer B**
   - Peer A initiates HTTPS connection to Peer B on port 39001
   - During TLS handshake, Peer B presents its certificate
   - Peer A's TOFU verifier checks if Peer B is known:
     - If new: trusts and stores the certificate fingerprint
     - If known: verifies the fingerprint matches

2. **Peer B initiates reverse connection**
   - After accepting the connection, Peer B extracts Peer A's IP address
   - Peer B immediately connects back to Peer A on port 39001
   - During this TLS handshake, Peer A presents its certificate
   - Peer B's TOFU verifier performs the same trust process

3. **Mutual Trust Established**
   - Both peers now have each other's certificate fingerprints stored
   - Future connections are verified against stored fingerprints
   - Any certificate changes are detected and warned about

## Implementation Details

### Server Side (main.rs)

When a connection is accepted:

```rust
let (stream, addr) = listener.accept().await?;
let client_ip = addr.ip();

// ... TLS handshake ...

// Initiate reverse connection
println!("Initiating reverse connection to {}:39001", client_ip);
match peer_client::connect_to_peer(&client_ip.to_string(), 39001, true).await {
    Ok(_) => println!("✓ Mutual trust established with {}", client_ip),
    Err(e) => println!("⚠ Reverse connection failed: {}. Continuing anyway...", e),
}
```

### Client Side (peer_client.rs)

The client uses a custom certificate verifier:

```rust
let verifier = TofuServerCertVerifier::new(peer_address);
let config = ClientConfig::builder()
    .with_safe_defaults()
    .with_custom_certificate_verifier(verifier)
    .with_no_client_auth();
```

### Certificate Verifier (cert_verifier.rs)

Implements TOFU logic:

```rust
impl ServerCertVerifier for TofuServerCertVerifier {
    fn verify_server_cert(...) -> Result<ServerCertVerified, TlsError> {
        // Calculate certificate fingerprint
        // Check if peer is known
        // If new: trust and store
        // If known: verify fingerprint matches
    }
}
```

## Security Benefits

1. **Mutual Authentication**: Both peers verify each other
2. **No Single Point of Failure**: No central CA required
3. **MITM Detection**: Certificate changes are detected
4. **Automatic Trust**: First connection automatically establishes trust
5. **Persistent Trust**: Relationships survive restarts

## Trust Database

Trusted peers are stored in `certs/trusted_peers.json`:

```json
{
  "peers": {
    "192.168.1.100:39001": {
      "fingerprint": "a1b2c3d4e5f6...",
      "first_seen": "1736437200",
      "last_seen": "1736437800"
    },
    "192.168.1.200:39001": {
      "fingerprint": "9z8y7x6w5v4u...",
      "first_seen": "1736437250",
      "last_seen": "1736437850"
    }
  }
}
```

## Testing Between Two Peers

### Setup

1. **On Machine A (192.168.1.100)**:
   ```bash
   cargo run
   ```
   Note the fingerprint displayed.

2. **On Machine B (192.168.1.200)**:
   ```bash
   cargo run
   ```
   Note the fingerprint displayed.

### Test Connection

From Machine A, use a tool like `curl` or create a simple Rust client:

```bash
curl -k https://192.168.1.200:39001/test
```

**Expected Output on Machine A:**
```
✓ Connected to peer: 192.168.1.200:39001
⚠ New peer: 192.168.1.200:39001 (fingerprint: 9z8y7x6w5v4u...)
  Auto-trusting (TOFU)
```

**Expected Output on Machine B:**
```
New connection from 192.168.1.100:51234
TLS connection established from 192.168.1.100
Initiating reverse connection to 192.168.1.100:39001
⚠ New peer: 192.168.1.100:39001 (fingerprint: a1b2c3d4e5f6...)
  Auto-trusting (TOFU)
✓ Mutual trust established with 192.168.1.100
```

### Verify Trust

On subsequent connections, you should see:
```
✓ Verified known peer: 192.168.1.100:39001
```

## Edge Cases Handled

### 1. Reverse Connection Fails
If the reverse connection fails (peer is behind NAT, firewall, etc.), the original connection continues:
```
⚠ Reverse connection failed: Connection refused. Continuing anyway...
```

### 2. Certificate Changed
If a peer's certificate changes (regenerated, MITM, etc.):
```
⚠ WARNING: Certificate changed for peer 192.168.1.100:39001!
  Expected: a1b2c3d4e5f6...
  Received: zzzzzzzzzzzzz...
  This could indicate a security issue!
```

### 3. Simultaneous Connections
If both peers connect to each other simultaneously, both reverse connections succeed and mutual trust is established.

## Port Requirements

- Both peers must listen on **port 39001**
- Both peers must be able to accept incoming connections
- If behind NAT/firewall, port 39001 must be forwarded

## Configuration Options

### Auto-Trust (Current Implementation)
```rust
peer_client::connect_to_peer(address, 39001, true).await
```
Automatically trusts new peers on first connection.

### Manual Trust (Future Enhancement)
```rust
peer_client::connect_to_peer(address, 39001, false).await
```
Would prompt for user approval before trusting new peers.

## Comparison to SSH

This implementation is similar to SSH's trust model:

| Feature | SSH | This Implementation |
|---------|-----|---------------------|
| Trust on first use | ✓ | ✓ |
| Fingerprint verification | ✓ | ✓ |
| Warning on change | ✓ | ✓ |
| Bidirectional | ✗ | ✓ |
| Automatic reverse | ✗ | ✓ |

## Troubleshooting

### "TLS handshake failed: CorruptMessage"
- This means the client is sending plain HTTP instead of HTTPS
- Use `https://` not `http://`
- Use a proper HTTPS client (curl with `-k` flag, or the Rust client)

### "Reverse connection failed"
- The peer might not be listening on port 39001
- Firewall might be blocking incoming connections
- The connection continues normally, but trust is one-directional

### "Certificate mismatch"
- A peer regenerated their certificate
- Possible MITM attack
- Remove the old entry from `certs/trusted_peers.json` to re-establish trust

## Future Enhancements

- [ ] Add manual trust approval option
- [ ] Implement certificate rotation protocol
- [ ] Add peer discovery mechanism
- [ ] Support multiple port configurations
- [ ] Add web UI for trust management
- [ ] Implement gossip protocol for trust propagation
