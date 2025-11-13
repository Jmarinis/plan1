use std::{fs, sync::Arc};
use std::collections::{HashSet, HashMap};
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use rustls::{ServerConfig, Certificate, PrivateKey};
use tokio_rustls::TlsAcceptor;
use tokio::io::{AsyncReadExt, AsyncWriteExt}; // Import the async traits
use serde::Serialize;
use std::net::IpAddr;

pub mod cert_manager;
pub mod peer_trust;
pub mod peer_client;
pub mod cert_verifier;
pub mod heartbeat;

// Macro for timestamped logging
macro_rules! log {
    ($($arg:tt)*) => {{
        let now = time::OffsetDateTime::now_utc();
        let timestamp = now.format(&time::format_description::well_known::Rfc3339).unwrap_or_else(|_| String::from("[TIME_ERROR]"));
        println!("[{}] {}", timestamp, format!($($arg)*));
    }};
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ConnectionInfo {
    hostname: String,
    ip_address: String,
    status: String,
    connected_at: String,
    last_message: String,
    last_message_time: String,
    request_count: usize,
    verified: bool,
    last_heartbeat_sent: Option<String>,
    last_heartbeat_received: Option<String>,
    alive: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Ensure certificate exists (generate if needed)
    cert_manager::ensure_certificate()?;
    
    // Display our certificate fingerprint
    let fingerprint = cert_manager::get_cert_fingerprint()?;
    log!("Our fingerprint: {}", fingerprint);
    
    // Create shared state for tracking verified peers
    let verified_peers: Arc<RwLock<HashSet<String>>> = Arc::new(RwLock::new(HashSet::new()));
    
    // Create shared state for tracking active connections
    let connections: Arc<RwLock<HashMap<String, ConnectionInfo>>> = Arc::new(RwLock::new(HashMap::new()));
    
    // Load TLS certificate and private key
    let certs = load_certs(cert_manager::get_cert_path())?;
    let key = load_private_key(cert_manager::get_key_path())?;

    // Configure rustls server without client authentication
    let config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| e.to_string())?;
    
    let acceptor = TlsAcceptor::from(Arc::new(config));

    // Bind HTTP listener on port 39000 (for monitor dashboard)
    let http_listener = TcpListener::bind("0.0.0.0:39000").await?;
    log!("HTTP monitor dashboard listening on port 39000");
    
    // Bind HTTPS listener on port 39001 (for secure communication)
    let https_listener = TcpListener::bind("0.0.0.0:39001").await?;
    log!("HTTPS server listening on port 39001 (all subsequent requests)");
    log!("Press Ctrl-C to shutdown gracefully");

    // Setup Ctrl-C handler
    let shutdown = Arc::new(tokio::sync::Notify::new());
    let shutdown_clone = shutdown.clone();
    
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.expect("Failed to listen for Ctrl-C");
        log!("[SHUTDOWN] Received Ctrl-C, shutting down gracefully...");
        shutdown_clone.notify_waiters();
    });

    // Reconnect to previously trusted peers on startup
    log!("[STARTUP] Loading previously trusted peers...");
    if let Ok(trusted) = peer_trust::TrustedPeers::load() {
        let peer_list = trusted.list_peers();
        log!("[STARTUP] Found {} previously trusted peers", peer_list.len());
        
        for (peer_addr, peer_info) in peer_list {
            // Parse address to get IP and port
            let parts: Vec<&str> = peer_addr.split(':').collect();
            if parts.len() != 2 {
                continue;
            }
            
            let peer_ip = parts[0].to_string();
            let peer_port = match parts[1].parse::<u16>() {
                Ok(p) => p,
                Err(_) => continue,
            };
            
            log!("[STARTUP] Attempting to reconnect to {} ({})", peer_addr, peer_info.hostname);
            
            let verified_peers_clone = verified_peers.clone();
            let connections_clone = connections.clone();
            let peer_addr_clone = peer_addr.clone();
            let peer_hostname = peer_info.hostname.clone();
            
            // Spawn reconnection attempt in background
            tokio::spawn(async move {
                // Add to verified peers before connecting to prevent loops
                {
                    let mut peers = verified_peers_clone.write().await;
                    peers.insert(peer_addr_clone.clone());
                }
                
                let reconnect_success = match peer_client::connect_to_peer(&peer_ip, peer_port, true).await {
                    Ok(_) => {
                        log!("[STARTUP] ✓ Successfully reconnected to {} ({})", peer_addr_clone, peer_hostname);
                        true
                    }
                    Err(e) => {
                        log!("[STARTUP] ⚠ Failed to reconnect to {}: {}", peer_addr_clone, e);
                        false
                    }
                };
                
                if reconnect_success {
                    // Add to connections tracking
                    let now_utc = time::OffsetDateTime::now_utc();
                    let timestamp = now_utc.format(&time::format_description::well_known::Rfc3339)
                        .unwrap_or_else(|_| String::from("unknown"));
                    
                    let mut conns = connections_clone.write().await;
                    conns.entry(peer_addr_clone.clone())
                        .or_insert_with(|| {
                            ConnectionInfo {
                                hostname: peer_hostname.clone(),
                                ip_address: peer_ip.clone(),
                                status: "Connected".to_string(),
                                connected_at: timestamp.clone(),
                                last_message: "Startup reconnection".to_string(),
                                last_message_time: timestamp,
                                request_count: 0,
                                verified: true,
                                last_heartbeat_sent: None,
                                last_heartbeat_received: None,
                                alive: true,
                            }
                        });
                } else {
                    // Remove from verified peers if connection failed
                    let mut peers = verified_peers_clone.write().await;
                    peers.remove(&peer_addr_clone);
                }
            });
        }
    } else {
        log!("[STARTUP] No previously trusted peers found");
    }
    
    // Start heartbeat background task
    let connections_heartbeat = connections.clone();
    let _heartbeat_task = heartbeat::start_heartbeat_task(connections_heartbeat);
    log!("[HEARTBEAT] Background heartbeat task started");
    
    // Spawn HTTP listener task for monitor dashboard
    let connections_http = connections.clone();
    let shutdown_http = shutdown.clone();
    let _http_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                result = http_listener.accept() => {
                    match result {
                        Ok((stream, addr)) => {
                            let client_ip = addr.ip();
                            log!("[HTTP] Monitor request from {} (port: {})", client_ip, addr.port());
                            
                            let connections_clone = connections_http.clone();
                            tokio::spawn(async move {
                                if let Err(e) = handle_http_monitor_dashboard(stream, client_ip, &connections_clone).await {
                                    log!("[ERROR] Monitor dashboard request failed: {:?}", e);
                                }
                            });
                        }
                        Err(e) => log!("[ERROR] HTTP listener error: {:?}", e),
                    }
                }
                _ = shutdown_http.notified() => {
                    log!("[SHUTDOWN] HTTP monitor listener shutting down");
                    break;
                }
            }
        }
    });

    // Handle HTTPS listener in main loop
    loop {
        tokio::select! {
            result = https_listener.accept() => {
                let (stream, addr) = result?;
        let client_ip = addr.ip();
        log!("[HTTPS] New connection from {} (port: {})", client_ip, addr.port());

        // Upgrade the TCP connection to TLS
        let acceptor = acceptor.clone();
        let connections_clone = connections.clone();
        let verified_peers_https = verified_peers.clone();
        tokio::spawn(async move {
            log!("[TLS] Starting TLS handshake with {}", client_ip);

            let tls_stream = acceptor.accept(stream).await;
            match tls_stream {
                Ok(mut stream) => {
                    log!("[TLS] ✓ Handshake successful with {}", client_ip);
                    
                    // Read the request first to check for custom port header
                    let mut buf = [0u8; 1024];
                    match stream.read(&mut buf).await {
                Ok(n) if n > 0 => {
                            // Parse the HTTP request
                            let request = String::from_utf8_lossy(&buf[..n]);
                            let first_line = request.lines().next().unwrap_or("<empty>");
                            log!("[HTTP] Request from {}: {}", client_ip, first_line);
                            
                            // Extract the path
                            let path = extract_path(&request).unwrap_or_else(|| "/".to_string());
                            
                            // Handle /heartbeat endpoint (respond to alive checks)
                            if path == "/heartbeat" {
                                log!("[HEARTBEAT] Received heartbeat request from {}", client_ip);
                                let response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nalive";
                                if let Err(e) = stream.write_all(response.as_bytes()).await {
                                    log!("[ERROR] Failed to send heartbeat response: {:?}", e);
                                }
                                return;
                            }
                            
                            // Handle /monitor endpoint (localhost only)
                            if path == "/monitor" {
                                if is_localhost(&client_ip) {
                                    if let Err(e) = handle_monitor_request(&mut stream, &connections_clone).await {
                                        log!("[ERROR] Monitor request failed: {:?}", e);
                                    }
                                } else {
                                    log!("[MONITOR] Rejected non-localhost request from {}", client_ip);
                                    let response = "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: 36\r\n\r\nMonitor endpoint only for localhost";
                                    let _ = stream.write_all(response.as_bytes()).await;
                                }
                                return;
                            }
                            
                            // Extract peer port and hostname from headers
                            let peer_port = extract_peer_port(&request).unwrap_or(39001);
                            let peer_hostname = extract_hostname(&request);
                            let peer_key = format!("{}:{}", client_ip, peer_port);
                            
                            // Update peer_trust with hostname if provided
                            if let Some(ref hostname) = peer_hostname {
                                if let Ok(mut trusted) = peer_trust::TrustedPeers::load() {
                                    if let Some(peer_info) = trusted.get_peer_info(&peer_key) {
                                        let fingerprint = peer_info.fingerprint.clone();
                                        let _ = trusted.add_peer(peer_key.clone(), fingerprint, Some(hostname.clone()));
                                        log!("[PEER] Updated hostname for {} to {}", peer_key, hostname);
                                    }
                                }
                            }
                            
                            // Check if peer is already verified
                            let already_verified = {
                                let peers = verified_peers_https.read().await;
                                peers.contains(&peer_key)
                            };
                            
                            let peer_verified = if already_verified {
                                log!("[PEER] Peer {} already verified, skipping certificate exchange", peer_key);
                                true
                            } else {
                                // Add to verified peers BEFORE initiating connection to prevent infinite loop
                                {
                                    let mut peers = verified_peers_https.write().await;
                                    peers.insert(peer_key.clone());
                                }
                                
                                // Initiate reverse connection to verify peer's certificate
                                log!("[PEER] Initiating reverse connection to {}", peer_key);
                                let connection_succeeded = match peer_client::connect_to_peer(&client_ip.to_string(), peer_port, true).await {
                                    Ok(_) => {
                                        log!("[PEER] ✓ Mutual trust established with {}", peer_key);
                                        
                                        // Exchange peer lists after successful verification
                                        let verified_peers_clone = verified_peers_https.clone();
                                        let connections_clone2 = connections_clone.clone();
                                        let client_ip_str = client_ip.to_string();
                                        tokio::spawn(async move {
                                            if let Err(e) = exchange_peer_lists(&client_ip_str, peer_port, &verified_peers_clone, &connections_clone2).await {
                                                log!("[MESH] Failed to exchange peer lists with {}: {}", client_ip_str, e);
                                            }
                                        });
                                        
                                        true
                                    }
                                    Err(e) => {
                                        log!("[PEER] ⚠ Reverse connection failed: {}", e.to_string());
                                        log!("[PEER] Note: This is normal if {} is not running a peer server", client_ip);
                                        false
                                    }
                                };
                                
                                // Remove from verified peers if connection failed
                                if !connection_succeeded {
                                    let mut peers = verified_peers_https.write().await;
                                    peers.remove(&peer_key);
                                }
                                
                                connection_succeeded
                            };
                            
                            // Track connection
                            {
                                let now_utc = time::OffsetDateTime::now_utc();
                                let timestamp = now_utc.format(&time::format_description::well_known::Rfc3339)
                                    .unwrap_or_else(|_| String::from("unknown"));
                                
                                let mut conns = connections_clone.write().await;
                                let is_new = !conns.contains_key(&peer_key);
                                conns.entry(peer_key.clone())
                                    .and_modify(|info| {
                                        info.request_count += 1;
                                        info.last_message = first_line.to_string();
                                        info.last_message_time = timestamp.clone();
                                        info.status = if peer_verified { "Connected".to_string() } else { "Unverified".to_string() };
                                        // Update hostname if provided
                                        if let Some(ref h) = peer_hostname {
                                            info.hostname = h.clone();
                                        }
                                    })
                                    .or_insert_with(|| {
                                        ConnectionInfo {
                                            hostname: peer_hostname.clone().unwrap_or_else(|| format!("peer-{}", client_ip)),
                                            ip_address: client_ip.to_string(),
                                            status: if peer_verified { "Connected".to_string() } else { "Unverified".to_string() },
                                            connected_at: timestamp.clone(),
                                            last_message: first_line.to_string(),
                                            last_message_time: timestamp,
                                            request_count: 1,
                                            verified: peer_verified,
                                            last_heartbeat_sent: None,
                                            last_heartbeat_received: None,
                                            alive: true,
                                        }
                                    });
                                if is_new {
                                    log!("[TRACK] Added new connection: {} (Total: {})", peer_key, conns.len());
                                } else {
                                    log!("[TRACK] Updated connection: {} (Total: {})", peer_key, conns.len());
                                }
                            }

                            // Build response with the path
                            let body = format!("Hello, World! Path: {}", path);
                            let response = format!("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}", body.len(), body);
                            log!("[HTTP] Sending 200 OK response for path: {}", path);
                            if let Err(e) = stream.write_all(response.as_bytes()).await {
                                log!("[ERROR] Failed to write response: {:?}", e);
                            } else {
                                log!("[HTTP] ✓ Response sent successfully to {}", client_ip);
                            }
                        }
                        Ok(_) => log!("[CONN] Connection closed by {}", client_ip),
                        Err(e) => log!("[ERROR] Read error from {}: {:?}", client_ip, e),
                    }
                }
                Err(e) => {
                    log!("[TLS] ✗ Handshake failed with {}: {:?}", client_ip, e);
                    log!("[TLS] Common causes:");
                    log!("[TLS]   - Browser rejecting self-signed certificate (accept security warning)");
                    log!("[TLS]   - Client doesn't have TOFU verifier (use Rust peer client)");
                    log!("[TLS]   - Certificate mismatch");
                },
            }
        });
            }
            _ = shutdown.notified() => {
                log!("[SHUTDOWN] HTTPS listener shutting down");
                break;
            }
        }
    }
    
    log!("[SHUTDOWN] Server stopped. Goodbye!");
    Ok(())
}

async fn handle_http_monitor_dashboard(
    mut stream: tokio::net::TcpStream,
    client_ip: IpAddr,
    connections: &Arc<RwLock<HashMap<String, ConnectionInfo>>>,
) -> Result<(), Box<dyn std::error::Error>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    
    // Read the HTTP request to determine the path
    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }
    
    let request = String::from_utf8_lossy(&buf[..n]);
    let path = extract_path(&request).unwrap_or_else(|| "/".to_string());
    
    // Handle /initiate endpoint
    if path == "/initiate" {
        log!("[INITIATE] Certificate exchange initiation requested from {}", client_ip);
        
        // Trigger certificate exchange with the requesting peer
        let peer_port = 39001; // Default HTTPS port
        let peer_key = format!("{}:{}", client_ip, peer_port);
        
        let connection_succeeded = peer_client::connect_to_peer(&client_ip.to_string(), peer_port, true).await.is_ok();
        
        if connection_succeeded {
            log!("[INITIATE] ✓ Successfully connected to peer: {}", peer_key);
            
            // Add to connections tracking
            let now_utc = time::OffsetDateTime::now_utc();
            let timestamp = now_utc.format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_else(|_| String::from("unknown"));
            
            let mut conns = connections.write().await;
            conns.entry(peer_key.clone())
                .or_insert_with(|| {
                    ConnectionInfo {
                        hostname: format!("peer-{}", client_ip),
                        ip_address: client_ip.to_string(),
                        status: "Connected".to_string(),
                        connected_at: timestamp.clone(),
                        last_message: "Initiated via /initiate".to_string(),
                        last_message_time: timestamp,
                        request_count: 1,
                        verified: true,
                        last_heartbeat_sent: None,
                        last_heartbeat_received: None,
                        alive: true,
                    }
                });
            log!("[INITIATE] Added connection: {} (Total: {})", peer_key, conns.len());
        } else {
            log!("[INITIATE] ⚠ Failed to connect to peer {}: connection error", peer_key);
        }
        
        // Redirect to dashboard
        let redirect_response = "HTTP/1.1 303 See Other\r\nLocation: /\r\nContent-Length: 0\r\n\r\n";
        stream.write_all(redirect_response.as_bytes()).await?;
        stream.flush().await?;
        
        log!("[INITIATE] Redirecting to dashboard");
        return Ok(());
    }
    
    // Serve dashboard for root path
    log!("[MONITOR] Serving HTML dashboard");
    
    // Get connection data
    let conns = connections.read().await;
    let mut conn_list: Vec<ConnectionInfo> = conns.values().cloned().collect();
    log!("[MONITOR] Found {} connections in HashMap", conn_list.len());
    conn_list.sort_by(|a, b| b.last_message_time.cmp(&a.last_message_time));
    
    // Build HTML table rows
    let table_rows: String = conn_list.iter().map(|conn| {
        let status_class = match conn.status.as_str() {
            "Connected" => "status-connected",
            "Unverified" => "status-unverified",
            _ => "status-disconnected",
        };
        
        let alive_status = if conn.alive { "&#x2713; Alive" } else { "&#x2717; Dead" };
        let alive_class = if conn.alive { "status-connected" } else { "status-disconnected" };
        
        let last_hb = conn.last_heartbeat_received.as_ref()
            .map(|s| format_timestamp_short(s))
            .unwrap_or_else(|| "Never".to_string());
        
        format!(
            "<tr>
                <td>{}</td>
                <td>{}</td>
                <td><span class=\"{}\">{}</span></td>
                <td><span class=\"{}\">{}</span></td>
                <td title=\"{}\">{}</td>
                <td title=\"{}\">{}</td>
                <td title=\"{}\">{}</td>
                <td>{}</td>
                <td title=\"{}\">{}</td>
            </tr>",
            conn.hostname,
            conn.ip_address,
            status_class,
            conn.status,
            alive_class,
            alive_status,
            conn.connected_at,
            format_timestamp_short(&conn.connected_at),
            conn.last_message,
            truncate(&conn.last_message, 50),
            conn.last_message_time,
            format_timestamp_short(&conn.last_message_time),
            conn.request_count,
            conn.last_heartbeat_received.as_ref().unwrap_or(&"Never".to_string()),
            last_hb,
        )
    }).collect::<Vec<_>>().join("\n");
    
    let html = format!(r#"<!DOCTYPE html>
<html>
<head>
    <title>Peer Monitor Dashboard</title>
    <meta http-equiv="refresh" content="5">
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }}
        h1 {{
            color: #333;
            border-bottom: 3px solid #4CAF50;
            padding-bottom: 10px;
        }}
        .info {{
            background-color: #e7f3fe;
            border-left: 6px solid #2196F3;
            padding: 10px;
            margin-bottom: 20px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background-color: white;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        th {{
            background-color: #4CAF50;
            color: white;
            padding: 12px;
            text-align: left;
            position: sticky;
            top: 0;
            cursor: pointer;
            user-select: none;
        }}
        th:hover {{
            background-color: #45a049;
        }}
        th.sort-asc::after {{
            content: ' \25B2';
            font-size: 0.8em;
        }}
        th.sort-desc::after {{
            content: ' \25BC';
            font-size: 0.8em;
        }}
        td {{
            padding: 10px;
            border-bottom: 1px solid #ddd;
        }}
        tr:hover {{
            background-color: #f5f5f5;
        }}
        .status-connected {{
            color: #4CAF50;
            font-weight: bold;
        }}
        .status-unverified {{
            color: #ff9800;
            font-weight: bold;
        }}
        .status-disconnected {{
            color: #f44336;
            font-weight: bold;
        }}
        .timestamp {{
            color: #666;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <h1>Peer Monitor</h1>
    <div class="info">
        <strong>Total Connections:</strong> {}<br>
        <strong>Last Updated:</strong> {} UTC<br>
        <em>Auto-refreshing every 5 seconds</em>
    </div>
    <table id="peerTable">
        <thead>
            <tr>
                <th onclick="sortTable(0)">Hostname</th>
                <th onclick="sortTable(1)">IP Address</th>
                <th onclick="sortTable(2)">Status</th>
                <th onclick="sortTable(3)">Alive</th>
                <th onclick="sortTable(4)">Connected At</th>
                <th onclick="sortTable(5)">Last Message</th>
                <th onclick="sortTable(6)">Last Message Time</th>
                <th onclick="sortTable(7)">Requests</th>
                <th onclick="sortTable(8)">Last Heartbeat</th>
            </tr>
        </thead>
        <tbody>
            {}
        </tbody>
    </table>
    <script>
        // Restore sort state from localStorage or initialize
        let sortDirections = JSON.parse(localStorage.getItem('sortDirections')) || {{}};
        let currentSortColumn = localStorage.getItem('currentSortColumn');
        
        function sortTable(columnIndex) {{
            const table = document.getElementById('peerTable');
            const tbody = table.querySelector('tbody');
            const rows = Array.from(tbody.querySelectorAll('tr'));
            const headers = table.querySelectorAll('th');
            
            // Toggle sort direction
            if (!sortDirections[columnIndex]) {{
                sortDirections[columnIndex] = 'asc';
            }} else if (sortDirections[columnIndex] === 'asc') {{
                sortDirections[columnIndex] = 'desc';
            }} else {{
                sortDirections[columnIndex] = 'asc';
            }}
            
            const direction = sortDirections[columnIndex];
            currentSortColumn = columnIndex;
            
            // Save sort state to localStorage
            localStorage.setItem('sortDirections', JSON.stringify(sortDirections));
            localStorage.setItem('currentSortColumn', currentSortColumn);
            
            // Remove sort indicators from all headers
            headers.forEach(h => {{
                h.classList.remove('sort-asc', 'sort-desc');
            }});
            
            // Add sort indicator to current header
            headers[columnIndex].classList.add(direction === 'asc' ? 'sort-asc' : 'sort-desc');
            
            // Sort rows
            rows.sort((a, b) => {{
                const aValue = a.cells[columnIndex].textContent.trim();
                const bValue = b.cells[columnIndex].textContent.trim();
                
                // Try to parse as numbers
                const aNum = parseFloat(aValue);
                const bNum = parseFloat(bValue);
                
                let comparison;
                if (!isNaN(aNum) && !isNaN(bNum)) {{
                    comparison = aNum - bNum;
                }} else {{
                    comparison = aValue.localeCompare(bValue);
                }}
                
                return direction === 'asc' ? comparison : -comparison;
            }});
            
            // Clear and re-append sorted rows
            tbody.innerHTML = '';
            rows.forEach(row => tbody.appendChild(row));
        }}
        
        // Apply saved sort on page load
        window.addEventListener('DOMContentLoaded', function() {{
            if (currentSortColumn !== null && currentSortColumn !== undefined) {{
                const columnIndex = parseInt(currentSortColumn);
                const headers = document.querySelectorAll('#peerTable th');
                const direction = sortDirections[columnIndex] || 'asc';
                
                // Restore sort indicator
                headers[columnIndex].classList.add(direction === 'asc' ? 'sort-asc' : 'sort-desc');
                
                // Re-apply sort
                const table = document.getElementById('peerTable');
                const tbody = table.querySelector('tbody');
                const rows = Array.from(tbody.querySelectorAll('tr'));
                
                rows.sort((a, b) => {{
                    const aValue = a.cells[columnIndex].textContent.trim();
                    const bValue = b.cells[columnIndex].textContent.trim();
                    
                    const aNum = parseFloat(aValue);
                    const bNum = parseFloat(bValue);
                    
                    let comparison;
                    if (!isNaN(aNum) && !isNaN(bNum)) {{
                        comparison = aNum - bNum;
                    }} else {{
                        comparison = aValue.localeCompare(bValue);
                    }}
                    
                    return direction === 'asc' ? comparison : -comparison;
                }});
                
                tbody.innerHTML = '';
                rows.forEach(row => tbody.appendChild(row));
            }}
        }});
    </script>
</body>
</html>"#,
        conn_list.len(),
        time::OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339).unwrap_or_else(|_| String::from("unknown")),
        table_rows
    );
    
    let response = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: text/html\r\n\
         Content-Length: {}\r\n\
         \r\n\
         {}",
        html.len(),
        html
    );
    
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;
    
    log!("[MONITOR] ✓ Dashboard served");
    Ok(())
}

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len])
    }
}

fn format_timestamp_short(timestamp: &str) -> String {
    // Format RFC3339 timestamp to show date and time
    // Input format: "2025-11-12T02:31:05Z"
    // Output format: "2025-11-12 02:31:05"
    if timestamp.len() >= 19 {
        format!("{} {}", &timestamp[0..10], &timestamp[11..19])
    } else {
        timestamp.to_string()
    }
}

// Exchange peer lists and discover new peers for mesh networking
async fn exchange_peer_lists(
    peer_ip: &str,
    peer_port: u16,
    verified_peers: &Arc<RwLock<HashSet<String>>>,
    connections: &Arc<RwLock<HashMap<String, ConnectionInfo>>>,
) -> Result<(), Box<dyn std::error::Error>> {
    log!("[MESH] Exchanging peer lists with {}:{}", peer_ip, peer_port);
    
    // Get our current verified peer list
    let our_peers: Vec<String> = {
        let peers = verified_peers.read().await;
        peers.iter().cloned().collect()
    };
    
    log!("[MESH] We have {} verified peers to share", our_peers.len());
    
    // Load trusted peers from file to get their peer lists
    let trusted = peer_trust::TrustedPeers::load()?;
    let all_trusted_peers = trusted.list_peers();
    
    // Build list of peer addresses to share (exclude the peer we're talking to)
    let current_peer = format!("{}:{}", peer_ip, peer_port);
    let peers_to_share: Vec<(String, String)> = all_trusted_peers
        .iter()
        .map(|(addr, info)| (addr.clone(), info.hostname.clone()))
        .filter(|(addr, _)| addr != &current_peer)
        .collect();
    
    log!("[MESH] Sharing {} trusted peer addresses", peers_to_share.len());
    
    // For each shared peer address, try to connect if not already verified
    for (peer_addr, peer_hostname) in peers_to_share {
        // Parse IP and port
        let parts: Vec<&str> = peer_addr.split(':').collect();
        if parts.len() != 2 {
            continue;
        }
        
        let new_peer_ip = parts[0].to_string();
        let new_peer_port = match parts[1].parse::<u16>() {
            Ok(p) => p,
            Err(_) => continue,
        };
        
        // Skip if already verified
        {
            let peers = verified_peers.read().await;
            if peers.contains(&peer_addr) {
                continue;
            }
        }
        
        // Try to connect to this new peer
        log!("[MESH] Discovered new peer from {}: {}", current_peer, peer_addr);
        log!("[MESH] Attempting to connect to {}", peer_addr);
        
        // Add to verified peers before connecting to prevent loops
        {
            let mut peers = verified_peers.write().await;
            peers.insert(peer_addr.clone());
        }
        
        // Spawn connection attempt
        let verified_peers_clone = verified_peers.clone();
        let connections_clone = connections.clone();
        let peer_addr_clone = peer_addr.clone();
        let new_peer_ip_clone = new_peer_ip.clone();
        let peer_hostname_clone = peer_hostname.clone();
        tokio::spawn(async move {
            let connection_succeeded = match peer_client::connect_to_peer(&new_peer_ip, new_peer_port, true).await {
                Ok(_) => {
                    log!("[MESH] ✓ Successfully connected to discovered peer: {}", peer_addr_clone);
                    true
                }
                Err(e) => {
                    log!("[MESH] ⚠ Failed to connect to discovered peer {}: {}", peer_addr_clone, e.to_string());
                    false
                }
            };
            
            if connection_succeeded {
                // Add to connections tracking
                let now_utc = time::OffsetDateTime::now_utc();
                let timestamp = now_utc.format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_else(|_| String::from("unknown"));
                
                let mut conns = connections_clone.write().await;
                conns.entry(peer_addr_clone.clone())
                    .or_insert_with(|| {
                        ConnectionInfo {
                            hostname: peer_hostname_clone.clone(),
                            ip_address: new_peer_ip_clone.clone(),
                            status: "Connected (Mesh)".to_string(),
                            connected_at: timestamp.clone(),
                            last_message: "Mesh discovery".to_string(),
                            last_message_time: timestamp,
                            request_count: 0,
                            verified: true,
                            last_heartbeat_sent: None,
                            last_heartbeat_received: None,
                            alive: true,
                        }
                    });
            } else {
                // Remove from verified peers if connection failed
                let mut peers = verified_peers_clone.write().await;
                peers.remove(&peer_addr_clone);
            }
        });
    }
    
    Ok(())
}

fn extract_peer_port(request: &str) -> Option<u16> {
    // Look for X-Peer-Port: header in the HTTP request
    // This allows clients to indicate which port their peer server is running on
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

fn extract_hostname(request: &str) -> Option<String> {
    // Look for X-Hostname: header in the HTTP request
    for line in request.lines() {
        if line.to_lowercase().starts_with("x-hostname:") {
            let hostname = line[11..].trim();
            if !hostname.is_empty() {
                return Some(hostname.to_string());
            }
        }
    }
    None
}

fn extract_path(request: &str) -> Option<String> {
    // Parse the first line of the HTTP request: "METHOD /path HTTP/version"
    let first_line = request.lines().next()?;
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() >= 2 {
        Some(parts[1].to_string())
    } else {
        None
    }
}

fn is_localhost(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(addr) => addr.is_loopback(),
        IpAddr::V6(addr) => addr.is_loopback(),
    }
}

async fn handle_monitor_request(
    stream: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    connections: &Arc<RwLock<HashMap<String, ConnectionInfo>>>,
) -> Result<(), Box<dyn std::error::Error>> {
    use tokio::io::AsyncWriteExt;
    
    log!("[MONITOR] Serving monitor request");
    
    // Get connection data
    let conns = connections.read().await;
    let conn_list: Vec<ConnectionInfo> = conns.values().cloned().collect();
    
    // Build JSON response
    let body = serde_json::json!({
        "total_connections": conn_list.len(),
        "connections": conn_list
    });
    let body_str = body.to_string();
    
    // Send response
    let response = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         \r\n\
         {}",
        body_str.len(),
        body_str
    );
    
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;
    
    log!("[MONITOR] ✓ Monitor data sent");
    Ok(())
}

fn load_certs(path: &str) -> Result<Vec<Certificate>, Box<dyn std::error::Error>> {
    let certfile = fs::File::open(path)?;
    let mut reader = std::io::BufReader::new(certfile);
    let certs = rustls_pemfile::certs(&mut reader)?
        .into_iter()
        .map(Certificate)
        .collect();
    Ok(certs)
}

fn load_private_key(path: &str) -> Result<PrivateKey, Box<dyn std::error::Error>> {
    let keyfile = fs::File::open(path)?;
    let mut reader = std::io::BufReader::new(keyfile);
    let keys = rustls_pemfile::pkcs8_private_keys(&mut reader)?
        .into_iter()
        .map(PrivateKey)
        .collect::<Vec<_>>();

    if keys.len() != 1 {
        return Err("Expected a single private key".into());
    }

    Ok(keys[0].clone())
}
