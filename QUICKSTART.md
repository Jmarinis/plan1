# Quick Start - P2P TOFU

## What Changed

Your application now automatically handles TLS certificates for peer-to-peer connections:

1. **Auto-generates certificates** on first run (stored in `certs/`)
2. **Trust-On-First-Use (TOFU)** - automatically trusts new peer certificates
3. **Certificate pinning** - verifies returning peers match their stored fingerprints
4. **Bidirectional trust** - when receiving a connection, automatically connects back to establish mutual trust

## Running Your Server

```bash
cargo run
```

On first run:
```
Generating new self-signed certificate...
Certificate generated successfully!
Fingerprint (SHA-256): 3686b2c12a667c0795107369426ff3920c19a75c714568798dc568e68c7f990e
Our fingerprint: 3686b2c12a667c0795107369426ff3920c19a75c714568798dc568e68c7f990e
HTTPS server listening on port 39001
```

On subsequent runs, it will reuse the existing certificate.

## Testing Locally

1. **Start the server**: `cargo run`
2. **Connect from browser**: `https://localhost:39001/test`
3. **Accept the security warning** (self-signed certificate)
4. You should see: `Hello, World! Path: /test`

## Files Created

```
certs/
├── server_cert.pem       # Your node's certificate
├── server_key.pem        # Your node's private key
└── trusted_peers.json    # Trusted peer fingerprints (created when peers connect)
```

## Key Benefits

- ✅ **No manual certificate management** - generated automatically
- ✅ **Works in any environment** - no CA or DNS required
- ✅ **Detects certificate changes** - warns if peer cert is different
- ✅ **Suitable for P2P** - each node is independent

## Security Note

The `CertificateUnknown` error you were seeing is **expected behavior** with self-signed certificates. The TOFU implementation handles this by:
- Tracking trusted peer fingerprints
- Auto-trusting on first connection
- Verifying on subsequent connections

For high-security scenarios, you can verify fingerprints out-of-band (phone, secure message) before trusting.

## Bidirectional Trust

When a peer connects to you:
1. Your server accepts the connection
2. **Automatically initiates a reverse connection** to the peer
3. Both peers exchange and verify certificates
4. Mutual trust is established

This ensures both peers trust each other, not just one-way trust.

## Next Steps

- `BIDIRECTIONAL_TRUST.md` - How mutual trust negotiation works
- `TOFU_README.md` - Detailed TOFU architecture and security
- Test with two peers on different machines using `curl -k https://peer-ip:39001/test`
