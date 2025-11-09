# X-Peer-Port Header

## Overview

The application supports a custom HTTP header `X-Peer-Port` to specify which port the peer server is running on. This enables bidirectional trust negotiation even when peers run on non-standard ports.

## How It Works

### Default Behavior (No Header)
When a client connects, the server:
1. Accepts the connection
2. Extracts the client's IP address
3. **Assumes** the peer server is on port 39001
4. Attempts reverse connection to `client_ip:39001`

### With X-Peer-Port Header
When a client includes the `X-Peer-Port` header:
1. Server extracts the custom port from the header
2. Attempts reverse connection to `client_ip:custom_port`

## Usage Examples

### Example 1: Default Port (39001)

**No header needed:**
```bash
curl -k https://server:39001/test
```

Server connects back to: `client_ip:39001`

### Example 2: Custom Port via Header

**Client running on port 39002:**
```bash
curl -k -H "X-Peer-Port: 39002" https://server:39001/test
```

Server connects back to: `client_ip:39002`

### Example 3: Browser with Custom Port

**JavaScript/Fetch:**
```javascript
fetch('https://server:39001/test', {
  headers: {
    'X-Peer-Port': '39002'
  }
})
```

**jQuery:**
```javascript
$.ajax({
  url: 'https://server:39001/test',
  headers: {
    'X-Peer-Port': '39002'
  }
})
```

### Example 4: Rust Client

```rust
use reqwest;

let client = reqwest::Client::builder()
    .danger_accept_invalid_certs(true)
    .build()?;

let response = client
    .get("https://server:39001/test")
    .header("X-Peer-Port", "39002")
    .send()
    .await?;
```

## Use Cases

### Use Case 1: Testing Multiple Peers on Same Machine
```bash
# Terminal 1: Peer on port 39001
cargo run --bin peer 39001

# Terminal 2: Peer on port 39002
cargo run --bin peer 39002

# Terminal 3: Connect from peer 2 to peer 1
curl -k -H "X-Peer-Port: 39002" https://127.0.0.1:39001/test
```

Both peers establish mutual trust!

### Use Case 2: Docker/Container Environments
Each container might expose different host ports:
```bash
# Container A: maps internal 39001 to host 40001
# Container B: maps internal 39001 to host 40002

curl -k -H "X-Peer-Port: 40002" https://containerA:40001/test
```

### Use Case 3: Firewall/NAT Scenarios
Some peers might only have specific ports open:
```bash
# Peer has only port 8443 open (not 39001)
curl -k -H "X-Peer-Port: 8443" https://server:39001/test
```

## Server Logs

### Without X-Peer-Port Header
```
TLS connection established from 192.168.1.100
Initiating reverse connection to 192.168.1.100:39001
✓ Mutual trust established with 192.168.1.100:39001
```

### With X-Peer-Port Header
```
TLS connection established from 192.168.1.100
Initiating reverse connection to 192.168.1.100:39002
✓ Mutual trust established with 192.168.1.100:39002
```

### When Reverse Connection Fails
```
TLS connection established from 192.168.1.100
Initiating reverse connection to 192.168.1.100:39002
⚠ Reverse connection failed: Connection refused. Continuing anyway...
```

## Technical Details

### Header Format
- **Name:** `X-Peer-Port` (case-insensitive)
- **Value:** Valid port number (1-65535)
- **Type:** Custom/Extension header

### Parsing Logic
```rust
fn extract_peer_port(request: &str) -> Option<u16> {
    for line in request.lines() {
        if line.to_lowercase().starts_with("x-peer-port:") {
            let port_str = line[13..].trim();
            if let Ok(port) = port_str.parse::<u16>() {
                return Some(port);
            }
        }
    }
    None
}

// Usage
let peer_port = extract_peer_port(&request).unwrap_or(39001);
```

### Security Considerations

#### Port Scanning Risk
- Malicious clients could specify arbitrary ports
- Server attempts connections to those ports
- **Mitigation:** Connection attempts are outbound-only, no data leakage

#### Port Range Validation
Currently accepts any valid port (1-65535). Could be restricted:
```rust
let peer_port = extract_peer_port(&request)
    .filter(|&p| p >= 30000 && p <= 40000)  // Restrict range
    .unwrap_or(39001);
```

#### DoS via Invalid Headers
- Invalid port values are ignored (default to 39001)
- No additional resource consumption

## Browser Compatibility

### Automatic Header Injection
Browsers don't automatically send custom headers. Options:

1. **JavaScript fetch/XHR** - Manual header injection
2. **Browser Extension** - Inject header automatically
3. **Proxy** - Add header at proxy level

### Example Browser Extension (Concept)
```javascript
chrome.webRequest.onBeforeSendHeaders.addListener(
  function(details) {
    details.requestHeaders.push({
      name: "X-Peer-Port",
      value: "39002"
    });
    return {requestHeaders: details.requestHeaders};
  },
  {urls: ["https://*/"]},
  ["blocking", "requestHeaders"]
);
```

## Testing

### Test Script
```bash
#!/bin/bash

# Start peer 1 on port 39001
cargo run --bin peer 39001 &
PID1=$!

# Start peer 2 on port 39002
cargo run --bin peer 39002 &
PID2=$!

sleep 2

# Test default port (should fail - no peer on 39001 from curl machine)
echo "Test 1: Default port"
curl -k https://localhost:39001/test

# Test with X-Peer-Port (should succeed)
echo "Test 2: Custom port"
curl -k -H "X-Peer-Port: 39002" https://localhost:39001/test

# Cleanup
kill $PID1 $PID2
```

## Limitations

1. **Single Port per Request:** One `X-Peer-Port` header per request
2. **No Multi-Peer:** Can't specify multiple peer ports in one request
3. **No Fallback List:** Can't provide fallback ports if first fails

## Future Enhancements

Possible improvements:
- [ ] Support port ranges: `X-Peer-Port: 39001-39005`
- [ ] Multiple ports: `X-Peer-Port: 39001,39002,39003`
- [ ] Service discovery: `X-Peer-Service: myapp` (lookup port)
- [ ] mDNS integration for local network peer discovery

## Summary

| Scenario | Header | Reverse Connection |
|----------|--------|-------------------|
| Default | None | `client_ip:39001` |
| Custom port | `X-Peer-Port: 8443` | `client_ip:8443` |
| Invalid port | `X-Peer-Port: abc` | `client_ip:39001` (fallback) |
| Out of range | `X-Peer-Port: 99999` | `client_ip:39001` (fallback) |

The `X-Peer-Port` header provides flexibility for P2P deployments while maintaining backward compatibility with the default port 39001.
