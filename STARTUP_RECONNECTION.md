# Startup Reconnection Feature

## Overview

The application now automatically attempts to reconnect to all previously trusted peers when it starts up. This ensures that the peer mesh network is quickly re-established after a restart.

## How It Works

### Startup Process

1. **Load Trusted Peers**: On startup, the application loads the list of previously trusted peers from `certs/trusted_peers.json`
2. **Parallel Reconnection**: For each peer, spawn a background task to attempt reconnection
3. **Certificate Verification**: Use existing TOFU verification to ensure the peer's certificate hasn't changed
4. **Connection Tracking**: Add successfully reconnected peers to the active connections list
5. **Cleanup**: Remove peers from the verified list if reconnection fails

### Logging

Startup reconnection activity is logged with `[STARTUP]` prefix:

```
[2025-11-13T02:36:04Z] [STARTUP] Loading previously trusted peers...
[2025-11-13T02:36:04Z] [STARTUP] Found 7 previously trusted peers
[2025-11-13T02:36:04Z] [STARTUP] Attempting to reconnect to 192.168.86.49:39001 (jims-m1-mini)
[2025-11-13T02:36:04Z] [STARTUP] Attempting to reconnect to 192.168.86.53:39001 (node02)
[2025-11-13T02:36:05Z] [STARTUP] ✓ Successfully reconnected to 192.168.86.49:39001 (jims-m1-mini)
[2025-11-13T02:36:05Z] [STARTUP] ⚠ Failed to reconnect to 192.168.86.250:39001: connection refused
```

### Benefits

- **Fast Mesh Restoration**: Network topology is quickly re-established after restarts
- **Automatic Recovery**: No manual intervention needed to restore connections
- **Non-Blocking**: Reconnection happens in parallel and doesn't delay server startup
- **Graceful Failure**: Failed reconnections are logged but don't prevent startup

## Dashboard Improvements

### Sort State Persistence

The dashboard now maintains column sort order across page refreshes using browser localStorage:

- **Sort Direction Saved**: When you sort a column, the direction (ascending/descending) is saved
- **Current Column Saved**: The currently sorted column index is remembered
- **Auto-Restore**: On page load, the saved sort is automatically reapplied
- **Survives Refreshes**: The 5-second auto-refresh maintains your chosen sort order

### Icon Display Fixes

Fixed character encoding issues for proper display of icons:

1. **Status Icons**: Checkmark (✓) and X (✗) now use HTML entities
   - `&#x2713;` for ✓ Alive
   - `&#x2717;` for ✗ Dead

2. **Sort Indicators**: Arrow symbols properly encoded in CSS
   - `\25B2` for ▲ (ascending)
   - `\25BC` for ▼ (descending)

### Technical Implementation

The dashboard uses JavaScript localStorage API:

```javascript
// Save sort state
localStorage.setItem('sortDirections', JSON.stringify(sortDirections));
localStorage.setItem('currentSortColumn', currentSortColumn);

// Restore on page load
let sortDirections = JSON.parse(localStorage.getItem('sortDirections')) || {};
let currentSortColumn = localStorage.getItem('currentSortColumn');

// Reapply sort automatically
window.addEventListener('DOMContentLoaded', function() {
    if (currentSortColumn !== null) {
        // Restore sort indicator and reorder rows
    }
});
```

## Configuration

No configuration is needed. The features work automatically:

- Startup reconnection uses the existing `certs/trusted_peers.json` file
- Sort state is stored in browser localStorage (per-browser, per-domain)

## Troubleshooting

### Startup Reconnection Issues

**Problem**: Peers not reconnecting on startup
- **Check**: Verify `certs/trusted_peers.json` contains the peer entries
- **Check**: Ensure the remote peers are running and accessible
- **Check**: Look for `[STARTUP]` log messages for specific errors

**Problem**: Some peers reconnect, others don't
- **Reason**: This is normal if some peers are offline or unreachable
- **Action**: Check network connectivity and firewall rules
- **Action**: Peers will be retried on the next heartbeat cycle (60 seconds)

### Dashboard Sort Issues

**Problem**: Sort order not maintained after refresh
- **Check**: Browser localStorage is enabled (not in private/incognito mode)
- **Check**: Browser console for JavaScript errors
- **Action**: Try clearing localStorage and setting sort order again

**Problem**: Icons not displaying correctly
- **Check**: Browser supports UTF-8 encoding
- **Check**: Font supports Unicode characters
- **Action**: The HTML entities should work in all modern browsers

## Security Considerations

### Startup Reconnection

- **TOFU Verification**: All reconnections use the same TOFU certificate verification as new connections
- **Certificate Pinning**: If a peer's certificate has changed, reconnection will fail (security feature)
- **No Auto-Trust**: Only previously trusted peers are contacted; no new peers are added

### Sort State Persistence

- **Client-Side Only**: Sort preferences stored in browser localStorage, not server
- **No Sensitive Data**: Only column index and direction are stored
- **Per-Browser**: Each browser maintains its own sort preferences

## Future Enhancements

Potential improvements:

- Configurable reconnection timeout
- Retry logic for failed reconnections
- Progress indicator in dashboard during startup reconnection
- Export/import of sort preferences
- Multiple saved sort configurations
