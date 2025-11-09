# Certificate Exchange Troubleshooting

## Understanding the Issue

The certificate exchange **IS working correctly** - the issue you're seeing is **expected behavior** when testing with browsers.

### What's Actually Happening

When you connect from a **browser**:
1. Browser sends HTTPS request (without custom TOFU verifier)
2. Server presents its self-signed certificate
3. **Browser rejects** the certificate (doesn't trust self-signed)
4. You see errors like `AlertReceived(CertificateUnknown)` or `AlertReceived(DecryptError)`

This is **normal and expected** - browsers don't have the TOFU verifier!

### The Solution

The bidirectional certificate exchange works when **both endpoints use the Rust TOFU client**, not browsers.

## How to Test Properly

### Option 1: Use the Peer Binary (RECOMMENDED)

The `peer` binary runs a full P2P node with both server and client capabilities.

**Terminal 1 - First Peer:**
```powershell
cargo run --bin peer 39001
```

**Terminal 2 - Second Peer (connect to first):**
```powershell
cargo run --bin peer 39002 127.0.0.1 39001
```

**Expected Output on Terminal 2:**
```
=== P2P Peer (Server + Client) ===

Our fingerprint: abc123...
Listening on port: 39002

✓ Server listening on port 39002
✓ Ready to accept connections

Initiating connection to 127.0.0.1:39001...
Connecting to peer: 127.0.0.1:39001
⚠ New peer: 127.0.0.1:39001 (fingerprint: def456...)
  Auto-trusting (TOFU)
✓ Connected to peer: 127.0.0.1:39001
✓ Successfully connected to peer
```

**Expected Output on Terminal 1:**
```
New connection from 127.0.0.1:xxxxx
✓ TLS connection established from 127.0.0.1
Initiating reverse connection to 127.0.0.1:39002
Connecting to peer: 127.0.0.1:39002
⚠ New peer: 127.0.0.1:39002 (fingerprint: abc123...)
  Auto-trusting (TOFU)
✓ Connected to peer: 127.0.0.1:39002
✓ Mutual trust established with 127.0.0.1
```

### Option 2: Browser Testing (With Limitations)

Browsers CAN connect, but you must:

1. **Navigate to:** `https://localhost:39001/test` (use HTTPS)
2. **Accept security warning** (click "Advanced" → "Proceed to localhost")
3. **Server will try reverse connection** but it will fail because browser isn't running a server

**What You'll See:**
```
Browser → Server: ✓ Works (after accepting warning)
Server → Browser: ✗ Fails (browser doesn't run server)
```

This is **one-way** trust, not bidirectional.

### Option 3: Using curl

```powershell
# Accept self-signed cert with -k flag
curl -k https://localhost:39001/test
```

**Output:**
```
Hello, World! Path: /test
```

Again, this is one-way (curl → server).

## Verifying Certificate Exchange

### Check Trusted Peers File

After successful bidirectional exchange:

```powershell
cat certs/trusted_peers.json
```

**You should see:**
```json
{
  "peers": {
    "127.0.0.1:39002": {
      "fingerprint": "abc123...",
      "first_seen": "1736437200",
      "last_seen": "1736437800"
    }
  }
}
```

### Both Peers Should Trust Each Other

- Peer 1's `trusted_peers.json` should contain Peer 2's fingerprint
- Peer 2's `trusted_peers.json` should contain Peer 1's fingerprint

## Common Errors and What They Mean

### `AlertReceived(CertificateUnknown)`
**Meaning:** Client doesn't trust the self-signed certificate  
**Cause:** Browser or client without TOFU verifier  
**Solution:** Use Rust peer client, or accept browser warning

### `AlertReceived(DecryptError)`  
**Meaning:** TLS handshake encryption mismatch  
**Cause:** Usually follows certificate rejection  
**Solution:** Same as above

### `TLS handshake failed: CorruptMessage`
**Meaning:** Plain HTTP sent to HTTPS port  
**Cause:** Using `http://` instead of `https://`  
**Solution:** Use `https://` or let the redirect work

### `Connection refused`
**Meaning:** No server listening on that port  
**Cause:** Peer not running or firewall blocking  
**Solution:** Ensure peer is running and ports are open

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                    Peer A (127.0.0.1:39001)                  │
│  ┌────────────────────────────────────────────────────┐     │
│  │ Server (with TOFU verifier)                       │     │
│  │ - Accepts connections                              │     │
│  │ - Initiates reverse connections                    │     │
│  └────────────────────────────────────────────────────┘     │
└─────────────────────────────────────────────────────────────┘
          │                                      ▲
          │ 1. Connect                           │ 2. Reverse
          │    (Present cert B)                  │    Connect
          ▼                                      │    (Present
┌─────────────────────────────────────────────────────────────┐
│                    Peer B (127.0.0.1:39002)                  │
│  ┌────────────────────────────────────────────────────┐     │
│  │ Server (with TOFU verifier)                       │     │
│  │ - Accepts connections                              │     │
│  │ - Initiates reverse connections                    │     │
│  └────────────────────────────────────────────────────┘     │
└─────────────────────────────────────────────────────────────┘

Result: Both peers trust each other's certificates ✓
```

## Why Browsers Show Errors

### What Browsers Do
1. Send HTTPS request to server
2. Server presents self-signed certificate
3. Browser checks against OS certificate store
4. Certificate NOT in store → **reject**
5. Show security warning to user

### What Rust Peer Does
1. Send HTTPS request to server
2. Server presents self-signed certificate  
3. **Custom TOFU verifier** checks `trusted_peers.json`
4. If new → **trust and store fingerprint**
5. If known → **verify fingerprint matches**

## Testing Checklist

- [ ] Both peers running with `cargo run --bin peer`
- [ ] Different ports (e.g., 39001 and 39002)
- [ ] One peer initiates connection to the other
- [ ] Both terminals show "✓ Mutual trust established"
- [ ] Both `certs/trusted_peers.json` files populated
- [ ] Subsequent connections show "✓ Verified known peer"

## Expected vs Actual Behavior

| Scenario | Expected | Actual | Status |
|----------|----------|--------|--------|
| Browser → Server | Warning shown | Warning shown | ✓ Correct |
| Browser accepts cert | Connection works | Connection works | ✓ Correct |
| Server → Browser reverse | Fails (no server) | Fails | ✓ Correct |
| Rust Peer → Rust Peer | Bidirectional trust | Bidirectional trust | ✓ Correct |
| Peer stores fingerprint | Yes | Yes | ✓ Correct |
| Peer verifies returning peer | Yes | Yes | ✓ Correct |

## Conclusion

The certificate exchange **IS working correctly**. The errors you see from browsers are **expected** because browsers don't have the TOFU verifier.

To see it working properly:
1. Use the `peer` binary on two terminals
2. Or deploy on two separate machines
3. Check `trusted_peers.json` on both sides

The bidirectional trust negotiation is **designed for peer-to-peer Rust applications**, not browser clients.
