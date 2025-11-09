# Logging Guide

## Log Prefixes

All log messages are prefixed with a category for easy filtering:

| Prefix | Meaning | Examples |
|--------|---------|----------|
| `[CONN]` | Connection events | New connections, closures |
| `[TLS]` | TLS/SSL operations | Handshakes, failures |
| `[HTTP]` | HTTP protocol | Requests, responses, redirects |
| `[PEER]` | Peer negotiation | Reverse connections, trust establishment |
| `[CERT]` | Certificate verification | TOFU operations, fingerprint checks |
| `[CLIENT]` | Outbound connections | Connecting to peers |
| `[ERROR]` | Error conditions | Failures, exceptions |

## Typical Connection Flow

### Browser Connection (Non-Peer)

**Successful HTTPS:**
```
[CONN] New connection from 192.168.1.100 (port: 54321)
[TLS] Starting TLS handshake with 192.168.1.100
[TLS] ✓ Handshake successful with 192.168.1.100
[HTTP] Request from 192.168.1.100: GET /test HTTP/1.1
[PEER] Initiating reverse connection to 192.168.1.100:39001
[CLIENT] Connecting to peer: 192.168.1.100:39001
[CLIENT] Establishing TCP connection...
[CLIENT] ✗ TLS handshake failed with 192.168.1.100:39001: Connection refused
[PEER] ⚠ Reverse connection failed: Connection refused (os error 111)
[PEER] Note: This is normal if 192.168.1.100 is not running a peer server
[HTTP] Sending 200 OK response for path: /test
[HTTP] ✓ Response sent successfully to 192.168.1.100
```

**What this means:**
- Browser connected successfully ✓
- TLS worked after accepting security warning ✓
- Server tried to connect back to browser (expected to fail) ✗
- Request processed and response sent ✓

### Peer-to-Peer Connection

**Successful bidirectional trust:**
```
[CONN] New connection from 192.168.1.200 (port: 39001)
[TLS] Starting TLS handshake with 192.168.1.200
[TLS] ✓ Handshake successful with 192.168.1.200
[HTTP] Request from 192.168.1.200: GET / HTTP/1.1
[PEER] Initiating reverse connection to 192.168.1.200:39001
[CLIENT] Connecting to peer: 192.168.1.200:39001
[CLIENT] Establishing TCP connection...
[CLIENT] ✓ TCP connected to 192.168.1.200:39001
[CLIENT] Starting TLS handshake...
[CERT] New peer detected: 192.168.1.200:39001
[CERT]   Fingerprint: abc123def456...
[CERT]   Auto-trusting (TOFU)
[CERT] ✓ Peer 192.168.1.200:39001 added to trusted list
[CLIENT] ✓ TLS handshake successful with 192.168.1.200:39001
[CLIENT] Sending HTTP request...
[CLIENT] ✓ Received response (45 bytes): HTTP/1.1 200 OK...
[PEER] ✓ Mutual trust established with 192.168.1.200:39001
[HTTP] Sending 200 OK response for path: /
[HTTP] ✓ Response sent successfully to 192.168.1.200
```

**What this means:**
- Peer connected ✓
- TLS handshake succeeded ✓
- Reverse connection succeeded ✓
- Certificate trusted via TOFU ✓
- Bidirectional trust established ✓

## Common Error Scenarios

### 1. Browser Rejecting Certificate

**Logs:**
```
[CONN] New connection from 192.168.1.100 (port: 54321)
[TLS] Starting TLS handshake with 192.168.1.100
[TLS] ✗ Handshake failed with 192.168.1.100: Custom { kind: InvalidData, error: AlertReceived(CertificateUnknown) }
[TLS] Common causes:
[TLS]   - Browser rejecting self-signed certificate (accept security warning)
[TLS]   - Client doesn't have TOFU verifier (use Rust peer client)
[TLS]   - Certificate mismatch
```

**Solution:** In your browser, accept the security warning for the self-signed certificate.

### 2. Certificate Fingerprint Mismatch

**Logs:**
```
[CERT] ✗ WARNING: Certificate changed for peer 192.168.1.200:39001!
[CERT]   Expected: abc123def456...
[CERT]   Received: zzz999yyy888...
[CERT]   This could indicate a security issue!
[CLIENT] ✗ TLS handshake failed with 192.168.1.200:39001: Certificate fingerprint mismatch
[PEER] ⚠ Reverse connection failed: Certificate fingerprint mismatch
```

**Causes:**
- Peer regenerated their certificate
- MITM attack
- Different node at same IP

**Solution:** 
- Verify with peer operator
- Remove old entry from `certs/trusted_peers.json`
- Reconnect to re-establish trust

### 3. Plain HTTP to HTTPS Port

**Logs:**
```
[CONN] New connection from 192.168.1.100 (port: 54321)
[HTTP] Plain HTTP detected from 192.168.1.100, sending 301 redirect
[HTTP] ✓ Redirected to: https://192.168.1.100:39001/test
```

**What this means:**
- Client sent HTTP instead of HTTPS
- Server sent redirect to HTTPS URL
- Client should automatically follow redirect

## Filtering Logs

### View only errors:
```bash
cargo run --bin plan1 2>&1 | grep "\[ERROR\]"
```

### View only peer negotiation:
```bash
cargo run --bin plan1 2>&1 | grep "\[PEER\]"
```

### View only certificate operations:
```bash
cargo run --bin plan1 2>&1 | grep "\[CERT\]"
```

### Exclude peer connection attempts:
```bash
cargo run --bin plan1 2>&1 | grep -v "\[PEER\]"
```

## Understanding TLS Handshake Failures

### `AlertReceived(CertificateUnknown)`
**Meaning:** Client doesn't trust the certificate  
**Common with:** Browsers, curl without `-k`  
**Solution:** Accept security warning or use TOFU client

### `AlertReceived(DecryptError)`
**Meaning:** Encryption negotiation failed  
**Usually follows:** Certificate rejection  
**Solution:** Same as CertificateUnknown

### `Custom { kind: InvalidData, error: CorruptMessage }`
**Meaning:** Plain HTTP sent to HTTPS port  
**Cause:** Using `http://` instead of `https://`  
**Solution:** Server auto-redirects, or use HTTPS directly

### `InvalidCertificateSignature`
**Meaning:** Certificate signature validation failed  
**Cause:** Missing signature bypass in verifier  
**Solution:** Already fixed in current version

## Debugging Tips

### 1. Check if Peer Server is Running
Look for reverse connection failure:
```
[PEER] ⚠ Reverse connection failed: Connection refused
```
This is **normal** if connecting from browser/curl.

### 2. Verify Certificate Exchange
Look for these logs on BOTH peers:
```
[CERT] ✓ Peer <address> added to trusted list
```

### 3. Confirm Trust Store
Check `certs/trusted_peers.json`:
```bash
cat certs/trusted_peers.json | jq
```

Should show peer fingerprints.

### 4. Test with Verbose Curl
```bash
curl -v -k https://localhost:39001/test
```

Look for SSL/TLS handshake details.

## Log Levels

### Success (✓)
- Operations completed successfully
- Expected outcomes

### Warning (⚠)
- Non-fatal issues
- Expected failures (e.g., reverse connection to browser)

### Error (✗)
- Fatal errors for that operation
- Unexpected conditions

## Performance Considerations

Logging is synchronous and may impact performance under high load. For production:

1. Consider using a logging framework (e.g., `tracing`, `log`)
2. Add log levels (DEBUG, INFO, WARN, ERROR)
3. Make logging configurable via environment variables

## Example: Two Peers Establishing Trust

**Peer A (192.168.1.100:39001) logs:**
```
[CONN] New connection from 192.168.1.200 (port: 39001)
[TLS] Starting TLS handshake with 192.168.1.200
[TLS] ✓ Handshake successful with 192.168.1.200
[HTTP] Request from 192.168.1.200: GET / HTTP/1.1
[PEER] Initiating reverse connection to 192.168.1.200:39001
[CLIENT] Connecting to peer: 192.168.1.200:39001
[CERT] New peer detected: 192.168.1.200:39001
[CERT]   Fingerprint: zzz999yyy888...
[CERT]   Auto-trusting (TOFU)
[CERT] ✓ Peer 192.168.1.200:39001 added to trusted list
[PEER] ✓ Mutual trust established with 192.168.1.200:39001
```

**Peer B (192.168.1.200:39001) logs:**
```
[CLIENT] Connecting to peer: 192.168.1.100:39001
[CERT] New peer detected: 192.168.1.100:39001
[CERT]   Fingerprint: abc123def456...
[CERT]   Auto-trusting (TOFU)
[CERT] ✓ Peer 192.168.1.100:39001 added to trusted list
[CLIENT] ✓ TLS handshake successful with 192.168.1.100:39001
```

Both peers now trust each other!
