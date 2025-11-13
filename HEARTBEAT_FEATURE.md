# Heartbeat Feature

## Overview

The application now sends "are you alive" heartbeat messages every minute to all nodes that have exchanged credentials (verified peers). The dashboard has been updated to show the alive status of each peer and includes sortable columns.

## Implementation Details

### 1. Heartbeat Module (`src/heartbeat.rs`)

A new module that handles:
- **Sending heartbeat requests** to verified peers via GET /heartbeat endpoint
- **Background task** that runs every 60 seconds
- **Connection state tracking** with last heartbeat sent/received timestamps
- **Alive/dead status** based on heartbeat responses

Key functions:
- `send_heartbeat_to_peer()` - Sends a single heartbeat to a specific peer
- `send_heartbeats_to_all()` - Iterates through all verified peers and sends heartbeats
- `start_heartbeat_task()` - Spawns the background task with 60-second interval

### 2. Heartbeat Endpoint

The server now responds to `/heartbeat` requests on the HTTPS port (39001):

```rust
// Handle /heartbeat endpoint (respond to alive checks)
if path == "/heartbeat" {
    log!("[HEARTBEAT] Received heartbeat request from {}", client_ip);
    let response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nalive";
    stream.write_all(response.as_bytes()).await?;
    return;
}
```

### 3. Enhanced ConnectionInfo Structure

Added three new fields to track heartbeat status:

```rust
pub(crate) struct ConnectionInfo {
    // ... existing fields ...
    last_heartbeat_sent: Option<String>,      // When we last sent a heartbeat
    last_heartbeat_received: Option<String>,  // When we last received a heartbeat response
    alive: bool,                              // Current alive status
}
```

### 4. Dashboard Updates

#### New Columns
- **Alive**: Shows ✓ Alive (green) or ✗ Dead (red)
- **Last Heartbeat**: Shows the timestamp of the last successful heartbeat

#### Sortable Columns
All columns are now sortable by clicking on the column header. Features:
- Click to toggle between ascending/descending sort
- Visual indicators (▲/▼) show current sort direction
- Hover effect on headers indicates clickability
- Numeric columns sort numerically, text columns alphabetically

The JavaScript sorting function handles:
```javascript
function sortTable(columnIndex) {
    // Toggles sort direction (asc <-> desc)
    // Adds visual indicators
    // Sorts rows with smart number/string detection
    // Updates DOM with sorted rows
}
```

## Usage

### Starting the Server

```bash
cargo run --bin plan1
```

The server will automatically:
1. Start the HTTPS listener on port 39001
2. Start the HTTP dashboard on port 39000
3. Launch the background heartbeat task
4. Begin sending heartbeats every 60 seconds to verified peers

### Monitoring

Access the dashboard at: http://localhost:39000

The dashboard:
- Auto-refreshes every 5 seconds
- Shows all connected peers with their alive status
- Displays last heartbeat times
- Allows sorting by any column

### Logs

Heartbeat activity is logged with `[HEARTBEAT]` prefix:

```
[2025-11-13T01:32:46Z] [HEARTBEAT] Background heartbeat task started
[2025-11-13T01:32:46Z] [HEARTBEAT] Starting heartbeat task (60 second interval)
[2025-11-13T01:33:46Z] [HEARTBEAT] Sending heartbeats to 3 peers
[2025-11-13T01:33:46Z] [HEARTBEAT] ✓ Peer 192.168.1.100:39001 is alive
[2025-11-13T01:33:47Z] [HEARTBEAT] ✗ Peer 192.168.1.101:39001 did not respond: connection timeout
[2025-11-13T01:33:47Z] [HEARTBEAT] Heartbeat round complete
```

## Status Indicators

- **Connected**: Peer is verified and last heartbeat succeeded
- **Unresponsive**: Peer failed to respond to last heartbeat
- **Unverified**: Peer has not completed TOFU certificate exchange

## Timing

- **Heartbeat Interval**: 60 seconds
- **Heartbeat Timeout**: 5 seconds per peer
- **Dashboard Refresh**: 5 seconds

## Technical Notes

### Concurrency
- Heartbeats are sent sequentially to avoid overwhelming the network
- Connection state is protected by `Arc<RwLock<HashMap<...>>>`
- Background task runs independently without blocking the main server

### Error Handling
- Failed heartbeats mark peers as "Unresponsive" but don't remove them
- Connection errors are logged but don't crash the server
- Timeouts prevent hanging on unresponsive peers

### Security
- Heartbeats use the same TOFU certificate verification as regular requests
- Only verified peers receive heartbeats
- Heartbeat endpoint is accessible to all (intentionally - it's just an alive check)

## Future Enhancements

Potential improvements:
- Configurable heartbeat interval
- Exponential backoff for repeatedly failing peers
- Automatic peer removal after N failed heartbeats
- Health metrics (average response time, uptime percentage)
- Heartbeat history graph in dashboard
