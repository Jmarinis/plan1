# P2P Trust-On-First-Use (TOFU) Implementation

This application implements a peer-to-peer TLS system with Trust-On-First-Use (TOFU) certificate validation.

## Features

- **Automatic Certificate Generation**: Each node generates its own self-signed certificate on first run
- **Certificate Fingerprinting**: SHA-256 fingerprints are used to identify and verify peers
- **Trust-On-First-Use**: New peer certificates are automatically trusted on first connection
- **Certificate Pinning**: Once trusted, peer certificates are verified on subsequent connections
- **Persistent Trust Store**: Trusted peer information is stored in `certs/trusted_peers.json`

## How It Works

### 1. Certificate Generation

On first run, the application:
- Creates a `certs/` directory
- Generates an ECDSA P-256 certificate and private key
- Saves them as `certs/server_cert.pem` and `certs/server_key.pem`
- Calculates and displays the certificate's SHA-256 fingerprint

### 2. Server Operation

The server:
- Listens for HTTPS connections on port 39001
- Uses the auto-generated certificate for TLS
- Displays its fingerprint on startup for sharing with peers

### 3. Peer Trust (TOFU)

When a peer connects:
- **First Connection**: The certificate fingerprint is automatically trusted and saved
- **Subsequent Connections**: The certificate is verified against the stored fingerprint
- **Certificate Change**: If a peer's certificate changes, a warning is displayed

### 4. Security Model

The TOFU approach provides:
- **Protection against later MITM attacks**: Once a peer is trusted, certificate changes are detected
- **No reliance on CAs**: Each peer is self-signed, suitable for P2P networks
- **Simple deployment**: No need for certificate distribution infrastructure

**Trade-offs**:
- Vulnerable to MITM on first connection (like SSH)
- Requires out-of-band fingerprint verification for high-security scenarios

## File Structure

```
certs/
├── server_cert.pem          # This node's certificate
├── server_key.pem           # This node's private key
└── trusted_peers.json       # Database of trusted peer fingerprints
```

## Usage Examples

### Starting the Server

```bash
cargo run
```

On first run, you'll see:
```
Generating new self-signed certificate...
Certificate generated successfully!
Fingerprint (SHA-256): a1b2c3d4e5f6...
Our fingerprint: a1b2c3d4e5f6...
HTTPS server listening on port 39001
```

### Connecting to Peers

Currently implemented as a server. To add client functionality, use the `peer_client` module:

```rust
use crate::peer_client;

// Connect to a peer with auto-trust
peer_client::connect_to_peer("192.168.1.100", 39001, true).await?;

// List trusted peers
peer_client::list_trusted_peers()?;

// Remove a peer from trusted list
peer_client::untrust_peer("192.168.1.100:39001")?;
```

## Trusted Peers Database Format

The `trusted_peers.json` file stores peer information:

```json
{
  "peers": {
    "192.168.1.100:39001": {
      "fingerprint": "a1b2c3d4e5f6...",
      "first_seen": "2025-01-09T15:30:00Z",
      "last_seen": "2025-01-09T16:45:00Z"
    }
  }
}
```

## Security Considerations

### For High Security Environments

1. **Verify fingerprints out-of-band**: Share fingerprints via secure channels (phone, encrypted messaging)
2. **Disable auto-trust**: Require manual approval for new peers
3. **Regular audits**: Review `trusted_peers.json` for unexpected entries
4. **Certificate rotation**: Implement a mechanism for legitimate certificate updates

### For Lab/Development

The current auto-trust implementation is suitable for:
- Internal networks
- Development environments
- Testing scenarios
- Low-risk P2P applications

## Future Enhancements

Possible improvements:
- Interactive trust prompts (manual approval)
- Certificate expiration handling
- Key rotation protocol
- Multi-factor peer authentication
- Web interface for trust management
- Integration with discovery protocols

## Comparison to Other Approaches

| Approach | Pros | Cons |
|----------|------|------|
| **TOFU (This)** | Simple, no infrastructure | Vulnerable on first connect |
| **Private CA** | Centralized control | Requires CA setup/maintenance |
| **Public CA** | Widely trusted | Not suitable for P2P/local |
| **No TLS** | Simplest | No encryption/authentication |

## Troubleshooting

### Certificate Unknown Error

If you see `AlertReceived(CertificateUnknown)`, the client doesn't trust self-signed certificates. This is expected - the client needs to implement TOFU as well.

### Certificate Mismatch Warning

If a peer's certificate changes, you'll see:
```
⚠ WARNING: Certificate changed for peer 192.168.1.100:39001!
  Expected: a1b2c3d4e5f6...
  Received: 9z8y7x6w5v4u...
  This could indicate a security issue!
```

**Possible causes**:
- Peer regenerated their certificate
- MITM attack
- Different node at same address

**Resolution**:
- Verify the change is legitimate with the peer operator
- Remove the old entry: manually edit `trusted_peers.json` or use `untrust_peer()`
- Reconnect to trust the new certificate
