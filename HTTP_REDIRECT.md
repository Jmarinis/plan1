# HTTP-to-HTTPS Automatic Redirect

## Overview

The server now automatically detects plain HTTP requests and redirects them to HTTPS.

## How It Works

### Detection
When a connection is received, the server:
1. **Peeks** at the first 5 bytes without consuming them
2. **Checks** if it starts with an HTTP method (GET, POST, PUT, HEAD, DELETE)
3. **Differentiates** between HTTP (plain text) and HTTPS (starts with TLS byte 0x16)

### Redirect Process
For plain HTTP requests:
1. Reads the complete HTTP request
2. Extracts the path (e.g., `/test`, `/api/status`)
3. Extracts the Host header if present
4. Sends HTTP 301 redirect to `https://host:39001/path`
5. Closes the connection

### Response Format
```http
HTTP/1.1 301 Moved Permanently
Location: https://hostname:39001/path
Content-Type: text/html
Content-Length: xxx
Connection: close

<html><body><h1>301 Moved Permanently</h1><p>This resource has moved to <a href="https://hostname:39001/path">HTTPS</a>.</p></body></html>
```

## Examples

### Example 1: Simple GET Request
**Client sends:**
```bash
curl http://localhost:39001/test
```

**Server responds:**
```http
HTTP/1.1 301 Moved Permanently
Location: https://localhost:39001/test
...
```

**Browser automatically follows to:** `https://localhost:39001/test`

### Example 2: With Host Header
**Client sends:**
```http
GET /api/status HTTP/1.1
Host: myserver.local
```

**Server redirects to:** `https://myserver.local:39001/api/status`

### Example 3: POST Request
**Client sends:**
```http
POST /data HTTP/1.1
Host: 192.168.1.100
```

**Server redirects to:** `https://192.168.1.100:39001/data`

## Server Output

When an HTTP request is detected:
```
New connection from 192.168.1.100:12345
Plain HTTP request detected from 192.168.1.100, sending redirect
Redirected HTTP request to: https://myserver:39001/test
```

When an HTTPS request is received:
```
New connection from 192.168.1.100:12346
TLS connection established from 192.168.1.100
...
```

## Implementation Details

### Protocol Detection
```rust
let mut peek_buf = [0u8; 5];
let is_http = if let Ok(n) = stream.peek(&mut peek_buf).await {
    // HTTP methods vs TLS handshake (0x16)
    n >= 4 && peek_buf[0] != 0x16 && 
    (
        peek_buf.starts_with(b"GET ") ||
        peek_buf.starts_with(b"POST") ||
        ...
    )
} else {
    false
};
```

### Benefits of Peeking
- Non-destructive: doesn't consume bytes from the stream
- Fast: only needs first few bytes
- Reliable: TLS always starts with 0x16 byte

## Browser Behavior

### Modern Browsers
- Automatically follow 301 redirects
- May cache the redirect (301 is permanent)
- Will show security warning for self-signed certificates

### Command Line Tools
```bash
# curl follows redirects with -L flag
curl -L http://localhost:39001/test

# wget follows redirects by default
wget http://localhost:39001/test
```

## Security Considerations

### Why 301 Instead of 307?
- **301 (Moved Permanently)**: Cached by browsers, permanent upgrade to HTTPS
- **307 (Temporary Redirect)**: Would require checking HTTP each time

### HSTS (Future Enhancement)
Could add `Strict-Transport-Security` header to force HTTPS:
```http
Strict-Transport-Security: max-age=31536000; includeSubDomains
```

### Attack Scenarios

#### SSL Stripping Attack (Mitigated)
- Attacker intercepts first HTTP request before redirect
- **Mitigation**: Use HSTS, or configure clients to use HTTPS directly

#### Certificate Warning (Expected)
- Self-signed certificates trigger browser warnings
- **Expected behavior** in P2P scenarios
- Trust established via TOFU mechanism

## Testing

### Test HTTP Redirect
```bash
# Should see 301 redirect
curl -v http://localhost:39001/test

# Should automatically follow to HTTPS
curl -L -k http://localhost:39001/test
```

### Test Direct HTTPS
```bash
# Should work without redirect
curl -k https://localhost:39001/test
```

### Test with Browser
1. Navigate to `http://localhost:39001/test`
2. Should be redirected to `https://localhost:39001/test`
3. Accept certificate warning
4. See the response

## Supported HTTP Methods

Currently detects:
- ✅ GET
- ✅ POST
- ✅ PUT
- ✅ HEAD
- ✅ DELETE

To add more methods, update the detection logic in `main.rs`.

## Performance Impact

- **Minimal**: Only one `peek()` call per connection
- **Fast**: Detection happens in microseconds
- **No overhead** for HTTPS connections

## Troubleshooting

### "Connection reset" error
- Normal for HTTP redirect - connection closes after sending 301
- Client should automatically reconnect to HTTPS URL

### Redirect loop
- Shouldn't happen - redirects go from HTTP → HTTPS only
- Check if proxy/load balancer is interfering

### Wrong redirect URL
- Check the Host header in your request
- Server uses Host header if present, otherwise uses IP address

## Future Enhancements

- [ ] Add HSTS support
- [ ] Make redirect URL configurable
- [ ] Support custom redirect messages
- [ ] Add metrics for HTTP vs HTTPS requests
- [ ] Option to reject HTTP instead of redirecting
