use std::{fs, sync::Arc, borrow::Cow};
use std::collections::{HashSet, HashMap};
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use rustls::{ServerConfig, Certificate, PrivateKey};
use tokio_rustls::TlsAcceptor;
use tokio::io::{AsyncReadExt, AsyncWriteExt}; // Import the async traits

use std::net::IpAddr;
use plan1::ConnectionInfo;

pub mod cert_manager;
pub mod peer_trust;
pub mod peer_client;
pub mod cert_verifier;
pub mod heartbeat;
pub mod broadcast;
pub mod config;

// Macro for timestamped logging
macro_rules! log {
    ($($arg:tt)*) => {{
        let now = time::OffsetDateTime::now_utc();
        let timestamp = now.format(&time::format_description::well_known::Rfc3339).unwrap_or_else(|_| String::from("[TIME_ERROR]"));
        println!("[{}] {}", timestamp, format!($($arg)*));
    }};
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

    // Load configuration
    let config = config::Config::load().unwrap_or_else(|_| {
        log!("Warning: Could not load config.toml, using defaults");
        config::Config::default()
    });

    log!("Loaded configuration: discovery_port={}, communication_port={}",
         config.network.discovery_port, config.network.communication_port);

    // Load TLS certificate and private key
    let certs = load_certs(&config.security.cert_path)?;
    let key = load_private_key(&config.security.key_path)?;

    // Configure rustls server without client authentication
    let tls_config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| e.to_string())?;

    let acceptor = TlsAcceptor::from(Arc::new(tls_config));

    // Bind discovery listener (initial contact point)
    let bind_addr = if config.network.bind_host.is_empty() {
        format!("[::]:{}", config.network.discovery_port)
    } else {
        format!("{}:{}", config.network.bind_host, config.network.discovery_port)
    };
    let discovery_listener = TcpListener::bind(&bind_addr).await?;
    log!("Discovery listener listening on {} (port {})", bind_addr, config.network.discovery_port);

    // Bind communication listener (negotiated secure communication)
    let comm_bind_addr = if config.network.bind_host.is_empty() {
        format!("[::]:{}", config.network.communication_port)
    } else {
        format!("{}:{}", config.network.bind_host, config.network.communication_port)
    };
    let communication_listener = TcpListener::bind(&comm_bind_addr).await?;
    log!("Communication listener listening on {} (port {})", comm_bind_addr, config.network.communication_port);

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

                    // Exchange peer lists with successfully reconnected peers
                    let verified_peers_exchange = verified_peers_clone.clone();
                    let connections_exchange = connections_clone.clone();
                    let peer_ip_exchange = peer_ip.clone();
                    tokio::spawn(async move {
                        if let Err(e) = exchange_peer_lists(&peer_ip_exchange, peer_port, &verified_peers_exchange, &connections_exchange).await {
                            log!("[STARTUP] Failed to exchange peer lists with {}: {}", peer_addr_clone, e);
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

    // Start broadcast listener background task
    let verified_peers_broadcast = verified_peers.clone();
    let connections_broadcast = connections.clone();
    let _broadcast_task = tokio::spawn(async move {
        if let Err(e) = broadcast::start_broadcast_listener(verified_peers_broadcast, connections_broadcast).await {
            log!("[BROADCAST] Error starting broadcast listener: {}", e);
        }
    });
    log!("[BROADCAST] Background broadcast listener task started");



    // Spawn discovery listener task
    let connections_discovery = connections.clone();
    let shutdown_discovery = shutdown.clone();
    let config_discovery = config.clone();
    let _discovery_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                result = discovery_listener.accept() => {
                    match result {
                        Ok((stream, addr)) => {
                            let client_ip = addr.ip();
                            let config_clone = config_discovery.clone();
                            tokio::spawn(async move {
                                if let Err(e) = handle_discovery_request(stream, client_ip, &config_clone).await {
                                    log!("[ERROR] Discovery request failed: {:?}", e);
                                }
                            });
                        }
                        Err(e) => log!("[ERROR] Discovery listener error: {:?}", e),
                    }
                }
                _ = shutdown_discovery.notified() => {
                    log!("[SHUTDOWN] Discovery listener shutting down");
                    break;
                }
            }
        }
    });

    // Handle communication listener in main loop
    loop {
        tokio::select! {
            result = communication_listener.accept() => {
        let (stream, addr) = result?;
        let client_ip = addr.ip();
        log!("[COMMUNICATION] New connection from {} (port: {})", client_ip, addr.port());

        // Upgrade the TCP connection to TLS
        let acceptor = acceptor.clone();
        let connections_clone = connections.clone();
        let verified_peers_comm = verified_peers.clone();
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

                            // Handle /api/status endpoint for AJAX updates
                            if path == "/api/status" {
                                log!("[API] Status request from {}", client_ip);

                                // Get node name
                                let node_name = match gethostname::gethostname().to_str() {
                                    Some(name) => name.to_string(),
                                    None => "Unknown".to_string(),
                                };

                                // Get connection data
                                let conns = connections_clone.read().await;
                                let mut conn_list: Vec<ConnectionInfo> = conns.values().cloned().collect();
                                conn_list.sort_by(|a, b| b.last_message_time.cmp(&a.last_message_time));

                                // Calculate statistics
                                let total_peers = conn_list.len();
                                let connected_count = conn_list.iter().filter(|c| c.status == "Connected").count();
                                let alive_count = conn_list.iter().filter(|c| c.alive).count();
                                let last_updated = time::OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339).unwrap_or_else(|_| String::from("unknown"));

                                // Build JSON response
                                let status_data = serde_json::json!({
                                    "node_name": node_name,
                                    "total_peers": total_peers,
                                    "connected_count": connected_count,
                                    "alive_count": alive_count,
                                    "last_updated": last_updated,
                                    "connections": conn_list
                                });

                                let body_str = status_data.to_string();
                                let response = format!(
                                    "HTTP/1.1 200 OK\r\n\
                                     Content-Type: application/json\r\n\
                                     Content-Length: {}\r\n\
                                     Connection: close\r\n\
                                     \r\n\
                                     {}",
                                    body_str.len(),
                                    body_str
                                );

                                if let Err(e) = stream.write_all(response.as_bytes()).await {
                                    log!("[ERROR] Failed to send API response: {:?}", e);
                                } else {
                                    log!("[API] ✓ Status data sent");
                                }
                                return;
                            }

                            // Handle /broadcast endpoint
                            if path == "/broadcast" {
                                log!("[BROADCAST] Manual broadcast requested from {}", client_ip);

                                // Send a broadcast message
                                if let Err(e) = broadcast::send_broadcast().await {
                                    log!("[BROADCAST] Error sending broadcast: {}", e);
                                } else {
                                    log!("[BROADCAST] ✓ Broadcast sent successfully");
                                }

                                // Redirect to dashboard
                                let redirect_response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 23\r\nConnection: close\r\n\r\nBroadcast sent successfully";
                                if let Err(e) = stream.write_all(redirect_response.as_bytes()).await {
                                    log!("[ERROR] Failed to send broadcast response: {:?}", e);
                                }
                                return;
                            }

                            // Handle /connect endpoint
                            if path.starts_with("/connect") {
                                // Extract hostname from query parameter
                                let hostname = if let Some(query_start) = path.find('?') {
                                    let query = &path[query_start + 1..];
                                    if let Some(host_param) = query.strip_prefix("hostname=") {
                                        Some(urlencoding::decode(host_param).unwrap_or_else(|_| Cow::Borrowed(host_param)).to_string())
                                    } else {
                                        None
                                    }
                                } else {
                                    None
                                };

                                if let Some(hostname) = hostname {
                                    if hostname.is_empty() {
                                        log!("[CONNECT] Empty hostname provided from {}", client_ip);
                                    } else {
                                        log!("[CONNECT] Connection requested to hostname '{}' from {}", hostname, client_ip);

                                        // Try to resolve hostname to IP
                                        match tokio::net::lookup_host(format!("{}:{}", hostname, config.network.communication_port)).await {
                                            Ok(mut addrs) => {
                                                if let Some(addr) = addrs.next() {
                                                    let peer_ip = addr.ip().to_string();
                                                    let peer_port = config.network.communication_port;
                                                    let peer_key = format!("{}:{}", peer_ip, peer_port);

                                                    log!("[CONNECT] Resolved '{}' to {}, attempting connection", hostname, peer_ip);

                                                    // Try to connect to the resolved peer
                                                    let connection_succeeded = peer_client::connect_to_peer(&peer_ip, peer_port, true).await.is_ok();

                                                    if connection_succeeded {
                                                        log!("[CONNECT] ✓ Successfully connected to {} ({})", peer_key, hostname);

                                                        // Add to connections tracking
                                                        let now_utc = time::OffsetDateTime::now_utc();
                                                        let timestamp = now_utc.format(&time::format_description::well_known::Rfc3339)
                                                            .unwrap_or_else(|_| String::from("unknown"));

                                                        let mut conns = connections_clone.write().await;
                                                        conns.entry(peer_key.clone())
                                                            .or_insert_with(|| {
                                                                ConnectionInfo {
                                                                    hostname: hostname.clone(),
                                                                    ip_address: peer_ip.clone(),
                                                                    status: "Connected (Manual)".to_string(),
                                                                    connected_at: timestamp.clone(),
                                                                    last_message: "Manual connection".to_string(),
                                                                    last_message_time: timestamp,
                                                                    request_count: 1,
                                                                    verified: true,
                                                                    last_heartbeat_sent: None,
                                                                    last_heartbeat_received: None,
                                                                    alive: true,
                                                                }
                                                            });
                                                        log!("[CONNECT] Added connection: {} (Total: {})", peer_key, conns.len());
                                                    } else {
                                                        log!("[CONNECT] ⚠ Failed to connect to {} ({})", peer_key, hostname);
                                                    }
                                                } else {
                                                    log!("[CONNECT] Could not resolve hostname '{}' from {}", hostname, client_ip);
                                                }
                                            }
                                            Err(e) => {
                                                log!("[CONNECT] DNS resolution failed for '{}' from {}: {}", hostname, client_ip, e);
                                            }
                                        }
                                    }
                                } else {
                                    log!("[CONNECT] No hostname parameter provided from {}", client_ip);
                                }

                                // Redirect to dashboard
                                let redirect_response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 19\r\nConnection: close\r\n\r\nConnection initiated";
                                if let Err(e) = stream.write_all(redirect_response.as_bytes()).await {
                                    log!("[ERROR] Failed to send connect response: {:?}", e);
                                }
                                return;
                            }

                            // Handle root path (serve dashboard)
                            if path == "/" {
                                if let Err(e) = handle_https_dashboard(&mut stream, &connections_clone).await {
                                    log!("[ERROR] Dashboard request failed: {:?}", e);
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
                                let peers = verified_peers_comm.read().await;
                                peers.contains(&peer_key)
                            };

                            let peer_verified = if already_verified {
                                log!("[PEER] Peer {} already verified, skipping certificate exchange", peer_key);
                                true
                            } else {
                                // Add to verified peers BEFORE initiating connection to prevent infinite loop
                                {
                                    let mut peers = verified_peers_comm.write().await;
                                    peers.insert(peer_key.clone());
                                }

                                // Initiate reverse connection to verify peer's certificate
                                log!("[PEER] Initiating reverse connection to {}", peer_key);
                                let connection_succeeded = match peer_client::connect_to_peer(&client_ip.to_string(), peer_port, true).await {
                                    Ok(_) => {
                                        log!("[PEER] ✓ Mutual trust established with {}", peer_key);

                                        // Exchange peer lists after successful verification
                                        let verified_peers_clone = verified_peers_comm.clone();
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
                                    let mut peers = verified_peers_comm.write().await;
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
                log!("[SHUTDOWN] Communication listener shutting down");
                break;
            }
        }
    }

    log!("[SHUTDOWN] Server stopped. Goodbye!");
    Ok(())
}

// Handle discovery requests (initial contact point)
async fn handle_discovery_request(
    mut stream: tokio::net::TcpStream,
    client_ip: IpAddr,
    config: &config::Config,
) -> Result<(), Box<dyn std::error::Error>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Read the request
    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }

    let request = String::from_utf8_lossy(&buf[..n]);
    let path = extract_path(&request).unwrap_or_else(|| "/".to_string());

    log!("[DISCOVERY] {} requested {}", client_ip, path);

    // Respond with communication port information
    let response_body = format!(r#"{{
        "communication_port": {},
        "node_info": {{
            "hostname": "{}",
            "ip_address": "{}"
        }}
    }}"#,
        config.network.communication_port,
        gethostname::gethostname().to_str().unwrap_or("unknown"),
        client_ip.to_string()
    );

    let response = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         X-Communication-Port: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {}",
        response_body.len(),
        config.network.communication_port,
        response_body
    );

    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;

    log!("[DISCOVERY] ✓ Sent communication port {} to {}", config.network.communication_port, client_ip);
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

    // Handle /broadcast endpoint
    if path == "/broadcast" {
        log!("[BROADCAST] Manual broadcast requested from {}", client_ip);

        // Send a broadcast message
        if let Err(e) = broadcast::send_broadcast().await {
            log!("[BROADCAST] Error sending broadcast: {}", e);
        } else {
            log!("[BROADCAST] ✓ Broadcast sent successfully");
        }

        // Redirect to dashboard
        let redirect_response = "HTTP/1.1 303 See Other\r\nLocation: /\r\nContent-Length: 0\r\n\r\n";
        stream.write_all(redirect_response.as_bytes()).await?;
        stream.flush().await?;

        log!("[BROADCAST] Redirecting to dashboard");
        return Ok(());
    }

    // Handle /api/status endpoint for AJAX updates
    if path == "/api/status" {
        log!("[API] Status request from {}", client_ip);

        // Get node name
        let node_name = match gethostname::gethostname().to_str() {
            Some(name) => name.to_string(),
            None => "Unknown".to_string(),
        };

        // Get connection data
        let conns = connections.read().await;
        let mut conn_list: Vec<ConnectionInfo> = conns.values().cloned().collect();
        conn_list.sort_by(|a, b| b.last_message_time.cmp(&a.last_message_time));

        // Calculate statistics
        let total_peers = conn_list.len();
        let connected_count = conn_list.iter().filter(|c| c.status == "Connected").count();
        let alive_count = conn_list.iter().filter(|c| c.alive).count();
        let last_updated = time::OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339).unwrap_or_else(|_| String::from("unknown"));

        // Build JSON response
        let status_data = serde_json::json!({
            "node_name": node_name,
            "total_peers": total_peers,
            "connected_count": connected_count,
            "alive_count": alive_count,
            "last_updated": last_updated,
            "connections": conn_list
        });

        let body_str = status_data.to_string();
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

        log!("[API] ✓ Status data sent");
        return Ok(());
    }

    // Handle /connect endpoint
    if path.starts_with("/connect") {
        // Extract hostname from query parameter
        let hostname = if let Some(query_start) = path.find('?') {
            let query = &path[query_start + 1..];
            if let Some(host_param) = query.strip_prefix("hostname=") {
                Some(urlencoding::decode(host_param).unwrap_or_else(|_| Cow::Borrowed(host_param)).to_string())
            } else {
                None
            }
        } else {
            None
        };

        if let Some(hostname) = hostname {
            if hostname.is_empty() {
                log!("[CONNECT] Empty hostname provided from {}", client_ip);
            } else {
                log!("[CONNECT] Connection requested to hostname '{}' from {}", hostname, client_ip);

                // Try to resolve hostname to IP
                match tokio::net::lookup_host(format!("{}:39001", hostname)).await {
                    Ok(mut addrs) => {
                        if let Some(addr) = addrs.next() {
                            let peer_ip = addr.ip().to_string();
                            let peer_port = 39001;
                            let peer_key = format!("{}:{}", peer_ip, peer_port);

                            log!("[CONNECT] Resolved '{}' to {}, attempting connection", hostname, peer_ip);

                            // Try to connect to the resolved peer
                            let connection_succeeded = peer_client::connect_to_peer(&peer_ip, peer_port, true).await.is_ok();

                            if connection_succeeded {
                                log!("[CONNECT] ✓ Successfully connected to {} ({})", peer_key, hostname);

                                // Add to connections tracking
                                let now_utc = time::OffsetDateTime::now_utc();
                                let timestamp = now_utc.format(&time::format_description::well_known::Rfc3339)
                                    .unwrap_or_else(|_| String::from("unknown"));

                                let mut conns = connections.write().await;
                                conns.entry(peer_key.clone())
                                    .or_insert_with(|| {
                                        ConnectionInfo {
                                            hostname: hostname.clone(),
                                            ip_address: peer_ip.clone(),
                                            status: "Connected (Manual)".to_string(),
                                            connected_at: timestamp.clone(),
                                            last_message: "Manual connection".to_string(),
                                            last_message_time: timestamp,
                                            request_count: 1,
                                            verified: true,
                                            last_heartbeat_sent: None,
                                            last_heartbeat_received: None,
                                            alive: true,
                                        }
                                    });
                                log!("[CONNECT] Added connection: {} (Total: {})", peer_key, conns.len());
                            } else {
                                log!("[CONNECT] ⚠ Failed to connect to {} ({})", peer_key, hostname);
                            }
                        } else {
                            log!("[CONNECT] Could not resolve hostname '{}' from {}", hostname, client_ip);
                        }
                    }
                    Err(e) => {
                        log!("[CONNECT] DNS resolution failed for '{}' from {}: {}", hostname, client_ip, e);
                    }
                }
            }
        } else {
            log!("[CONNECT] No hostname parameter provided from {}", client_ip);
        }

        // Redirect to dashboard
        let redirect_response = "HTTP/1.1 303 See Other\r\nLocation: /\r\nContent-Length: 0\r\n\r\n";
        stream.write_all(redirect_response.as_bytes()).await?;
        stream.flush().await?;

        log!("[CONNECT] Redirecting to dashboard");
        return Ok(());
    }

    // Serve dashboard for root path
    log!("[MONITOR] Serving HTML dashboard");

    // Get node name
    let node_name = match gethostname::gethostname().to_str() {
        Some(name) => name.to_string(),
        None => "Unknown".to_string(),
    };
    log!("[MONITOR] Node name: {}", node_name);

    // Get connection data
    let conns = connections.read().await;
    let mut conn_list: Vec<ConnectionInfo> = conns.values().cloned().collect();
    log!("[MONITOR] Found {} connections in HashMap", conn_list.len());
    conn_list.sort_by(|a, b| b.last_message_time.cmp(&a.last_message_time));

    // Calculate statistics
    let total_peers = conn_list.len();
    let connected_count = conn_list.iter().filter(|c| c.status == "Connected").count();
    let alive_count = conn_list.iter().filter(|c| c.alive).count();
    let last_updated = time::OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339).unwrap_or_else(|_| String::from("unknown"));

    // Build simplified node cards
    let node_cards: String = conn_list.iter().map(|conn| {
        let status_class = match conn.status.as_str() {
            "Connected" => "status-connected",
            "Unverified" => "status-unverified",
            _ => "status-disconnected",
        };

        let alive_icon = if conn.alive { "&#x2713;" } else { "&#x2717;" };
        let alive_class = if conn.alive { "status-connected" } else { "status-disconnected" };

        let last_seen = conn.last_heartbeat_received.as_ref()
            .map(|s| format_timestamp_short(s))
            .unwrap_or_else(|| "Never".to_string());

        format!(r#"
        <div class="node-card" data-hostname="{}" data-ip="{}">
            <div class="node-header">
                <div class="node-info">
                    <h3 class="node-hostname">{}</h3>
                    <div class="node-ip">{}</div>
                </div>
                <div class="node-status">
                    <span class="{}">{}</span>
                    <span class="{} alive-indicator">{}</span>
                </div>
            </div>
            <div class="node-details">
                <div class="detail-item"><span class="detail-label">Last Seen:</span> {}</div>
                <div class="detail-item"><span class="detail-label">Connected:</span> {}</div>
                <div class="detail-item"><span class="detail-label">Requests:</span> {}</div>
            </div>
            <div class="node-actions">
                <button class="btn btn-secondary show-status-btn" onclick="showNodeStatus('{}', '{}')">Show Status</button>
                <button class="btn btn-primary connect-btn" onclick="connectToNode('{}')">Connect</button>
            </div>
        </div>"#,
            conn.hostname, conn.ip_address,
            conn.hostname,
            conn.ip_address,
            status_class, conn.status,
            alive_class, alive_icon,
            last_seen,
            format_timestamp_short(&conn.connected_at),
            conn.request_count,
            conn.hostname, conn.ip_address,
            conn.hostname
        )
    }).collect::<Vec<_>>().join("\n");

    let html = format!(r#"<!DOCTYPE html>
<html>
<head>
    <title>Peer Status - {}</title>
    <link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>&#128279;</text></svg>">
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
            color: #333;
        }}
        .header {{
            background: linear-gradient(135deg, #4CAF50, #45a049);
            color: white;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        h1 {{
            margin: 0;
            font-size: 2em;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        .hos-status {{
            background: rgba(255,255,255,0.1);
            padding: 15px;
            border-radius: 6px;
            margin-top: 15px;
        }}
        .hos-status h2 {{
            margin: 0 0 10px 0;
            font-size: 1.2em;
        }}
        .controls {{
            display: flex;
            gap: 15px;
            align-items: center;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }}
        .search-box {{
            padding: 8px 12px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 14px;
            width: 250px;
        }}
        .btn {{
            padding: 8px 16px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
            transition: all 0.2s;
        }}
        .btn-primary {{
            background-color: #2196F3;
            color: white;
        }}
        .btn-primary:hover {{
            background-color: #1976D2;
        }}
        .btn-secondary {{
            background-color: #757575;
            color: white;
        }}
        .btn-secondary:hover {{
            background-color: #616161;
        }}
        .stats {{
            display: flex;
            gap: 20px;
            margin-top: 10px;
        }}
        .stat {{
            background: rgba(255,255,255,0.1);
            padding: 10px;
            border-radius: 4px;
            text-align: center;
        }}
        .stat-number {{
            font-size: 1.5em;
            font-weight: bold;
        }}
        .nodes-section {{
            background-color: white;
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }}
        .nodes-section h2 {{
            margin: 0 0 15px 0;
            color: #333;
            border-bottom: 2px solid #4CAF50;
            padding-bottom: 10px;
        }}
        .nodes-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
            gap: 15px;
        }}
        .node-card {{
            border: 1px solid #ddd;
            border-radius: 8px;
            padding: 15px;
            background: white;
            transition: box-shadow 0.2s;
        }}
        .node-card:hover {{
            box-shadow: 0 4px 8px rgba(0,0,0,0.1);
        }}
        .node-header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 10px;
        }}
        .node-info h3 {{
            margin: 0 0 5px 0;
            font-size: 1.1em;
            color: #333;
        }}
        .node-ip {{
            color: #666;
            font-size: 0.9em;
        }}
        .node-status {{
            text-align: right;
        }}
        .node-details {{
            margin-bottom: 15px;
            font-size: 0.9em;
        }}
        .detail-item {{
            margin-bottom: 5px;
        }}
        .detail-label {{
            font-weight: bold;
            color: #666;
        }}
        .node-actions {{
            display: flex;
            gap: 10px;
            justify-content: flex-end;
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
        .alive-indicator {{
            font-size: 1.2em;
            margin-left: 5px;
        }}
        .no-nodes {{
            text-align: center;
            padding: 40px;
            color: #666;
            font-style: italic;
        }}
        @media (max-width: 768px) {{
            .controls {{
                flex-direction: column;
                align-items: stretch;
            }}
            .search-box {{
                width: 100%;
            }}
            .stats {{
                flex-wrap: wrap;
            }}
            .nodes-grid {{
                grid-template-columns: 1fr;
            }}
            .node-header {{
                flex-direction: column;
                gap: 10px;
            }}
            .node-status {{
                text-align: left;
            }}
            .node-actions {{
                justify-content: center;
            }}
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>&#128279; Peer Status - {}</h1>
        <div class="hos-status">
            <h2>HOS Status</h2>
            <div><strong>Node Name:</strong> {}</div>
            <div><strong>Status:</strong> <span class="status-connected">Online & Running</span></div>
            <div><strong>Last Updated:</strong> {} UTC</div>
        </div>
        <div class="stats">
            <div class="stat">
                <div class="stat-number">{}</div>
                <div>Total Peers</div>
            </div>
            <div class="stat">
                <div class="stat-number">{}</div>
                <div>Connected</div>
            </div>
            <div class="stat">
                <div class="stat-number">{}</div>
                <div>Alive</div>
            </div>
        </div>
    </div>

    <div class="controls">
        <input type="text" id="searchInput" class="search-box" placeholder="Search nodes...">
        <button id="refreshBtn" class="btn btn-primary">&#128259; Refresh Now</button>
        <button id="clearBtn" class="btn btn-secondary">&#128465; Clear Search</button>
    </div>

    <div class="controls">
        <button id="broadcastBtn" class="btn btn-primary" style="background-color: #FF9800;">&#128226; Send Broadcast</button>
        <input type="text" id="hostnameInput" class="search-box" placeholder="Enter hostname to connect..." style="margin-left: 15px;">
        <button id="connectBtn" class="btn btn-primary">&#128279; Connect to Host</button>
    </div>

    <div class="nodes-section">
        <h2>Known Nodes</h2>
        <div class="nodes-grid" id="nodesGrid">
            {}
        </div>
        <div id="noNodes" class="no-nodes" style="display: none;">
            No nodes found
        </div>
    </div>

    <script>
        let searchTerm = '';
        let updateInterval;

        // Get DOM elements
        const searchInput = document.getElementById('searchInput');
        const refreshBtn = document.getElementById('refreshBtn');
        const clearBtn = document.getElementById('clearBtn');
        const broadcastBtn = document.getElementById('broadcastBtn');
        const hostnameInput = document.getElementById('hostnameInput');
        const connectBtn = document.getElementById('connectBtn');
        const nodesGrid = document.getElementById('nodesGrid');
        const noNodes = document.getElementById('noNodes');

        // Store original node cards
        const originalCards = Array.from(nodesGrid.querySelectorAll('.node-card'));

        function filterNodes(term) {{
            searchTerm = term.toLowerCase();
            let visibleCount = 0;

            originalCards.forEach(card => {{
                const hostname = card.dataset.hostname.toLowerCase();
                const ip = card.dataset.ip.toLowerCase();
                const text = card.textContent.toLowerCase();

                const isVisible = hostname.includes(searchTerm) ||
                                ip.includes(searchTerm) ||
                                text.includes(searchTerm);

                card.style.display = isVisible ? '' : 'none';
                if (isVisible) visibleCount++;
            }});

            noNodes.style.display = visibleCount === 0 && searchTerm ? 'block' : 'none';
        }}

        function refreshPage() {{
            location.reload();
        }}

        function showNodeStatus(hostname, ip) {{
            // Show detailed status for the node
            const statusDetails = 'Node: ' + hostname + '\\nIP: ' + ip + '\\n\\nDetailed status information would be shown here in a future enhancement.';
            alert(statusDetails);
        }}

        function connectToNode(hostname) {{
            // Use the existing connect endpoint
            const encodedHostname = encodeURIComponent(hostname);
            fetch('/connect?hostname=' + encodedHostname)
                .then(response => {{
                    if (response.ok) {{
                        alert('Successfully initiated connection to ' + hostname);
                        location.reload();
                    }} else {{
                        alert('Failed to connect to ' + hostname);
                    }}
                }})
                .catch(error => {{
                    console.error('Connect error:', error);
                    alert('Failed to connect to ' + hostname);
                }});
        }}

        // Event listeners
        searchInput.addEventListener('input', (e) => {{
            filterNodes(e.target.value);
        }});

        refreshBtn.addEventListener('click', refreshPage);

        clearBtn.addEventListener('click', () => {{
            searchInput.value = '';
            filterNodes('');
        }});

        broadcastBtn.addEventListener('click', () => {{
            fetch('/broadcast')
                .then(response => {{
                    if (response.ok) {{
                        alert('Broadcast sent successfully');
                        location.reload();
                    }} else {{
                        alert('Failed to send broadcast');
                    }}
                }})
                .catch(error => {{
                    console.error('Broadcast error:', error);
                    alert('Failed to send broadcast');
                }});
        }});

        connectBtn.addEventListener('click', () => {{
            const hostname = hostnameInput.value.trim();
            if (hostname) {{
                const encodedHostname = encodeURIComponent(hostname);
                fetch('/connect?hostname=' + encodedHostname)
                    .then(response => {{
                        if (response.ok) {{
                            hostnameInput.value = '';
                            alert('Successfully initiated connection to ' + hostname);
                            location.reload();
                        }} else {{
                            alert('Failed to connect to ' + hostname);
                        }}
                    }})
                    .catch(error => {{
                        console.error('Connect error:', error);
                        alert('Failed to connect to ' + hostname);
                    }});
            }} else {{
                alert('Please enter a hostname');
                hostnameInput.focus();
            }}
        }});

        hostnameInput.addEventListener('keypress', (e) => {{
            if (e.key === 'Enter') {{
                connectBtn.click();
            }}
        }});

        // Keyboard shortcuts
        document.addEventListener('keydown', (e) => {{
            if (e.ctrlKey || e.metaKey) {{
                if (e.key === 'f') {{
                    e.preventDefault();
                    searchInput.focus();
                }} else if (e.key === 'r') {{
                    e.preventDefault();
                    refreshPage();
                }}
            }}
        }});

        function updateStatus() {{
            fetch('/api/status')
                .then(response => response.json())
                .then(data => {{
                    // Update statistics
                    document.querySelector('.stat:nth-child(1) .stat-number').textContent = data.total_peers;
                    document.querySelector('.stat:nth-child(2) .stat-number').textContent = data.connected_count;
                    document.querySelector('.stat:nth-child(3) .stat-number').textContent = data.alive_count;

                    // Update last updated time
                    const lastUpdatedElement = document.querySelector('.hos-status div:last-child strong:last-child');
                    if (lastUpdatedElement) {{
                        const timestamp = data.last_updated;
                        const date = new Date(timestamp);
                        const formatted = date.toLocaleString();
                        lastUpdatedElement.textContent = formatted + ' UTC';
                    }}

                    // Update node cards
                    updateNodeCards(data.connections);
                }})
                .catch(error => {{
                    console.error('Error updating status:', error);
                }});
        }}

        function updateNodeCards(connections) {{
            const nodesGrid = document.getElementById('nodesGrid');
            const noNodes = document.getElementById('noNodes');

            if (connections.length === 0) {{
                nodesGrid.innerHTML = '';
                noNodes.style.display = 'block';
                return;
            }}

            noNodes.style.display = 'none';

            // Create new node cards
            const cardsHtml = connections.map(conn => {{
                const statusClass = conn.status === 'Connected' ? 'status-connected' :
                                   conn.status === 'Unverified' ? 'status-unverified' : 'status-disconnected';
                const aliveIcon = conn.alive ? '&#x2713;' : '&#x2717;';
                const aliveClass = conn.alive ? 'status-connected' : 'status-disconnected';

                const lastSeen = conn.last_heartbeat_received ?
                    new Date(conn.last_heartbeat_received).toLocaleString() : 'Never';

                return '<div class="node-card" data-hostname="' + conn.hostname + '" data-ip="' + conn.ip_address + '">' +
                    '<div class="node-header">' +
                        '<div class="node-info">' +
                            '<h3 class="node-hostname">' + conn.hostname + '</h3>' +
                            '<div class="node-ip">' + conn.ip_address + '</div>' +
                        '</div>' +
                        '<div class="node-status">' +
                            '<span class="' + statusClass + '">' + conn.status + '</span>' +
                            '<span class="' + aliveClass + ' alive-indicator">' + aliveIcon + '</span>' +
                        '</div>' +
                    '</div>' +
                    '<div class="node-details">' +
                        '<div class="detail-item"><span class="detail-label">Last Seen:</span> ' + lastSeen + '</div>' +
                        '<div class="detail-item"><span class="detail-label">Connected:</span> ' + new Date(conn.connected_at).toLocaleString() + '</div>' +
                        '<div class="detail-item"><span class="detail-label">Requests:</span> ' + conn.request_count + '</div>' +
                    '</div>' +
                    '<div class="node-actions">' +
                        '<button class="btn btn-secondary show-status-btn" onclick="showNodeStatus(\'' + conn.hostname + '\', \'' + conn.ip_address + '\')">Show Status</button>' +
                        '<button class="btn btn-primary connect-btn" onclick="connectToNode(\'' + conn.hostname + '\')">Connect</button>' +
                    '</div>' +
                '</div>';
            }}).join('');

            nodesGrid.innerHTML = cardsHtml;

            // Update original cards reference for filtering
            originalCards.length = 0;
            originalCards.push(...nodesGrid.querySelectorAll('.node-card'));

            // Re-apply current search filter
            if (searchTerm) {{
                filterNodes(searchTerm);
            }}
        }}

        // Focus search input on page load
        window.addEventListener('DOMContentLoaded', function() {{
            if (searchInput.value) {{
                searchInput.focus();
            }}

            // Start automatic updates every 5 seconds
            updateStatus(); // Initial update
            updateInterval = setInterval(updateStatus, 5000);
        }});

        // Clean up interval when page unloads
        window.addEventListener('beforeunload', function() {{
            if (updateInterval) {{
                clearInterval(updateInterval);
            }}
        }});
    </script>
</body>
</html>"#,
        node_name,
        node_name,
        node_name,
        last_updated,
        total_peers,
        connected_count,
        alive_count,
        node_cards
    );

    let response = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: text/html\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
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

async fn handle_https_dashboard(
    stream: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    connections: &Arc<RwLock<HashMap<String, ConnectionInfo>>>,
) -> Result<(), Box<dyn std::error::Error>> {
    use tokio::io::AsyncWriteExt;

    // Serve dashboard for root path
    log!("[DASHBOARD] Serving HTTPS HTML dashboard");

    // Get node name
    let node_name = match gethostname::gethostname().to_str() {
        Some(name) => name.to_string(),
        None => "Unknown".to_string(),
    };
    log!("[DASHBOARD] Node name: {}", node_name);

    // Get connection data
    let conns = connections.read().await;
    let mut conn_list: Vec<ConnectionInfo> = conns.values().cloned().collect();
    log!("[DASHBOARD] Found {} connections in HashMap", conn_list.len());
    conn_list.sort_by(|a, b| b.last_message_time.cmp(&a.last_message_time));

    // Calculate statistics
    let total_peers = conn_list.len();
    let connected_count = conn_list.iter().filter(|c| c.status == "Connected").count();
    let alive_count = conn_list.iter().filter(|c| c.alive).count();
    let last_updated = time::OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339).unwrap_or_else(|_| String::from("unknown"));

    // Build simplified node cards
    let node_cards: String = conn_list.iter().map(|conn| {
        let status_class = match conn.status.as_str() {
            "Connected" => "status-connected",
            "Unverified" => "status-unverified",
            _ => "status-disconnected",
        };

        let alive_icon = if conn.alive { "&#x2713;" } else { "&#x2717;" };
        let alive_class = if conn.alive { "status-connected" } else { "status-disconnected" };

        let last_seen = conn.last_heartbeat_received.as_ref()
            .map(|s| format_timestamp_short(s))
            .unwrap_or_else(|| "Never".to_string());

        format!(r#"
        <div class="node-card" data-hostname="{}" data-ip="{}">
            <div class="node-header">
                <div class="node-info">
                    <h3 class="node-hostname">{}</h3>
                    <div class="node-ip">{}</div>
                </div>
                <div class="node-status">
                    <span class="{}">{}</span>
                    <span class="{} alive-indicator">{}</span>
                </div>
            </div>
            <div class="node-details">
                <div class="detail-item"><span class="detail-label">Last Seen:</span> {}</div>
                <div class="detail-item"><span class="detail-label">Connected:</span> {}</div>
                <div class="detail-item"><span class="detail-label">Requests:</span> {}</div>
            </div>
            <div class="node-actions">
                <button class="btn btn-secondary show-status-btn" onclick="showNodeStatus('{}', '{}')">Show Status</button>
                <button class="btn btn-primary connect-btn" onclick="connectToNode('{}')">Connect</button>
            </div>
        </div>"#,
            conn.hostname, conn.ip_address,
            conn.hostname,
            conn.ip_address,
            status_class, conn.status,
            alive_class, alive_icon,
            last_seen,
            format_timestamp_short(&conn.connected_at),
            conn.request_count,
            conn.hostname, conn.ip_address,
            conn.hostname
        )
    }).collect::<Vec<_>>().join("\n");

    let html = format!(r#"<!DOCTYPE html>
<html>
<head>
    <title>Peer Status - {}</title>
    <link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>&#128279;</text></svg>">
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
            color: #333;
        }}
        .header {{
            background: linear-gradient(135deg, #4CAF50, #45a049);
            color: white;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        h1 {{
            margin: 0;
            font-size: 2em;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        .hos-status {{
            background: rgba(255,255,255,0.1);
            padding: 15px;
            border-radius: 6px;
            margin-top: 15px;
        }}
        .hos-status h2 {{
            margin: 0 0 10px 0;
            font-size: 1.2em;
        }}
        .controls {{
            display: flex;
            gap: 15px;
            align-items: center;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }}
        .search-box {{
            padding: 8px 12px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 14px;
            width: 250px;
        }}
        .btn {{
            padding: 8px 16px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
            transition: all 0.2s;
        }}
        .btn-primary {{
            background-color: #2196F3;
            color: white;
        }}
        .btn-primary:hover {{
            background-color: #1976D2;
        }}
        .btn-secondary {{
            background-color: #757575;
            color: white;
        }}
        .btn-secondary:hover {{
            background-color: #616161;
        }}
        .stats {{
            display: flex;
            gap: 20px;
            margin-top: 10px;
        }}
        .stat {{
            background: rgba(255,255,255,0.1);
            padding: 10px;
            border-radius: 4px;
            text-align: center;
        }}
        .stat-number {{
            font-size: 1.5em;
            font-weight: bold;
        }}
        .nodes-section {{
            background-color: white;
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }}
        .nodes-section h2 {{
            margin: 0 0 15px 0;
            color: #333;
            border-bottom: 2px solid #4CAF50;
            padding-bottom: 10px;
        }}
        .nodes-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
            gap: 15px;
        }}
        .node-card {{
            border: 1px solid #ddd;
            border-radius: 8px;
            padding: 15px;
            background: white;
            transition: box-shadow 0.2s;
        }}
        .node-card:hover {{
            box-shadow: 0 4px 8px rgba(0,0,0,0.1);
        }}
        .node-header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 10px;
        }}
        .node-info h3 {{
            margin: 0 0 5px 0;
            font-size: 1.1em;
            color: #333;
        }}
        .node-ip {{
            color: #666;
            font-size: 0.9em;
        }}
        .node-status {{
            text-align: right;
        }}
        .node-details {{
            margin-bottom: 15px;
            font-size: 0.9em;
        }}
        .detail-item {{
            margin-bottom: 5px;
        }}
        .detail-label {{
            font-weight: bold;
            color: #666;
        }}
        .node-actions {{
            display: flex;
            gap: 10px;
            justify-content: flex-end;
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
        .alive-indicator {{
            font-size: 1.2em;
            margin-left: 5px;
        }}
        .no-nodes {{
            text-align: center;
            padding: 40px;
            color: #666;
            font-style: italic;
        }}
        @media (max-width: 768px) {{
            .controls {{
                flex-direction: column;
                align-items: stretch;
            }}
            .search-box {{
                width: 100%;
            }}
            .stats {{
                flex-wrap: wrap;
            }}
            .nodes-grid {{
                grid-template-columns: 1fr;
            }}
            .node-header {{
                flex-direction: column;
                gap: 10px;
            }}
            .node-status {{
                text-align: left;
            }}
            .node-actions {{
                justify-content: center;
            }}
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>&#128279; Peer Status - {}</h1>
        <div class="hos-status">
            <h2>HOS Status</h2>
            <div><strong>Node Name:</strong> {}</div>
            <div><strong>Status:</strong> <span class="status-connected">Online & Running</span></div>
            <div><strong>Last Updated:</strong> {} UTC</div>
        </div>
        <div class="stats">
            <div class="stat">
                <div class="stat-number">{}</div>
                <div>Total Peers</div>
            </div>
            <div class="stat">
                <div class="stat-number">{}</div>
                <div>Connected</div>
            </div>
            <div class="stat">
                <div class="stat-number">{}</div>
                <div>Alive</div>
            </div>
        </div>
    </div>

    <div class="controls">
        <input type="text" id="searchInput" class="search-box" placeholder="Search nodes...">
        <button id="refreshBtn" class="btn btn-primary">&#128259; Refresh Now</button>
        <button id="clearBtn" class="btn btn-secondary">&#128465; Clear Search</button>
    </div>

    <div class="controls">
        <button id="broadcastBtn" class="btn btn-primary" style="background-color: #FF9800;">&#128226; Send Broadcast</button>
        <input type="text" id="hostnameInput" class="search-box" placeholder="Enter hostname to connect..." style="margin-left: 15px;">
        <button id="connectBtn" class="btn btn-primary">&#128279; Connect to Host</button>
    </div>

    <div class="nodes-section">
        <h2>Known Nodes</h2>
        <div class="nodes-grid" id="nodesGrid">
            {}
        </div>
        <div id="noNodes" class="no-nodes" style="display: none;">
            No nodes found
        </div>
    </div>

    <script>
        let searchTerm = '';
        let updateInterval;

        // Get DOM elements
        const searchInput = document.getElementById('searchInput');
        const refreshBtn = document.getElementById('refreshBtn');
        const clearBtn = document.getElementById('clearBtn');
        const broadcastBtn = document.getElementById('broadcastBtn');
        const hostnameInput = document.getElementById('hostnameInput');
        const connectBtn = document.getElementById('connectBtn');
        const nodesGrid = document.getElementById('nodesGrid');
        const noNodes = document.getElementById('noNodes');

        // Store original node cards
        const originalCards = Array.from(nodesGrid.querySelectorAll('.node-card'));

        function filterNodes(term) {{
            searchTerm = term.toLowerCase();
            let visibleCount = 0;

            originalCards.forEach(card => {{
                const hostname = card.dataset.hostname.toLowerCase();
                const ip = card.dataset.ip.toLowerCase();
                const text = card.textContent.toLowerCase();

                const isVisible = hostname.includes(searchTerm) ||
                                ip.includes(searchTerm) ||
                                text.includes(searchTerm);

                card.style.display = isVisible ? '' : 'none';
                if (isVisible) visibleCount++;
            }});

            noNodes.style.display = visibleCount === 0 && searchTerm ? 'block' : 'none';
        }}

        function refreshPage() {{
            location.reload();
        }}

        function showNodeStatus(hostname, ip) {{
            // Show detailed status for the node
            const statusDetails = 'Node: ' + hostname + '\\nIP: ' + ip + '\\n\\nDetailed status information would be shown here in a future enhancement.';
            alert(statusDetails);
        }}

        function connectToNode(hostname) {{
            // Use the existing connect endpoint
            const encodedHostname = encodeURIComponent(hostname);
            fetch('/connect?hostname=' + encodedHostname)
                .then(response => {{
                    if (response.ok) {{
                        alert('Successfully initiated connection to ' + hostname);
                        location.reload();
                    }} else {{
                        alert('Failed to connect to ' + hostname);
                    }}
                }})
                .catch(error => {{
                    console.error('Connect error:', error);
                    alert('Failed to connect to ' + hostname);
                }});
        }}

        // Event listeners
        searchInput.addEventListener('input', (e) => {{
            filterNodes(e.target.value);
        }});

        refreshBtn.addEventListener('click', refreshPage);

        clearBtn.addEventListener('click', () => {{
            searchInput.value = '';
            filterNodes('');
        }});

        broadcastBtn.addEventListener('click', () => {{
            fetch('/broadcast')
                .then(response => {{
                    if (response.ok) {{
                        alert('Broadcast sent successfully');
                        location.reload();
                    }} else {{
                        alert('Failed to send broadcast');
                    }}
                }})
                .catch(error => {{
                    console.error('Broadcast error:', error);
                    alert('Failed to send broadcast');
                }});
        }});

        connectBtn.addEventListener('click', () => {{
            const hostname = hostnameInput.value.trim();
            if (hostname) {{
                const encodedHostname = encodeURIComponent(hostname);
                fetch('/connect?hostname=' + encodedHostname)
                    .then(response => {{
                        if (response.ok) {{
                            hostnameInput.value = '';
                            alert('Successfully initiated connection to ' + hostname);
                            location.reload();
                        }} else {{
                            alert('Failed to connect to ' + hostname);
                        }}
                    }})
                    .catch(error => {{
                        console.error('Connect error:', error);
                        alert('Failed to connect to ' + hostname);
                    }});
            }} else {{
                alert('Please enter a hostname');
                hostnameInput.focus();
            }}
        }});

        hostnameInput.addEventListener('keypress', (e) => {{
            if (e.key === 'Enter') {{
                connectBtn.click();
            }}
        }});

        // Keyboard shortcuts
        document.addEventListener('keydown', (e) => {{
            if (e.ctrlKey || e.metaKey) {{
                if (e.key === 'f') {{
                    e.preventDefault();
                    searchInput.focus();
                }} else if (e.key === 'r') {{
                    e.preventDefault();
                    refreshPage();
                }}
            }}
        }});

        function updateStatus() {{
            fetch('/api/status')
                .then(response => response.json())
                .then(data => {{
                    // Update statistics
                    document.querySelector('.stat:nth-child(1) .stat-number').textContent = data.total_peers;
                    document.querySelector('.stat:nth-child(2) .stat-number').textContent = data.connected_count;
                    document.querySelector('.stat:nth-child(3) .stat-number').textContent = data.alive_count;

                    // Update last updated time
                    const lastUpdatedElement = document.querySelector('.hos-status div:last-child strong:last-child');
                    if (lastUpdatedElement) {{
                        const timestamp = data.last_updated;
                        const date = new Date(timestamp);
                        const formatted = date.toLocaleString();
                        lastUpdatedElement.textContent = formatted + ' UTC';
                    }}

                    // Update node cards
                    updateNodeCards(data.connections);
                }})
                .catch(error => {{
                    console.error('Error updating status:', error);
                }});
        }}

        function updateNodeCards(connections) {{
            const nodesGrid = document.getElementById('nodesGrid');
            const noNodes = document.getElementById('noNodes');

            if (connections.length === 0) {{
                nodesGrid.innerHTML = '';
                noNodes.style.display = 'block';
                return;
            }}

            noNodes.style.display = 'none';

            // Create new node cards
            const cardsHtml = connections.map(conn => {{
                const statusClass = conn.status === 'Connected' ? 'status-connected' :
                                   conn.status === 'Unverified' ? 'status-unverified' : 'status-disconnected';
                const aliveIcon = conn.alive ? '&#x2713;' : '&#x2717;';
                const aliveClass = conn.alive ? 'status-connected' : 'status-disconnected';

                const lastSeen = conn.last_heartbeat_received ?
                    new Date(conn.last_heartbeat_received).toLocaleString() : 'Never';

                return '<div class="node-card" data-hostname="' + conn.hostname + '" data-ip="' + conn.ip_address + '">' +
                    '<div class="node-header">' +
                        '<div class="node-info">' +
                            '<h3 class="node-hostname">' + conn.hostname + '</h3>' +
                            '<div class="node-ip">' + conn.ip_address + '</div>' +
                        '</div>' +
                        '<div class="node-status">' +
                            '<span class="' + statusClass + '">' + conn.status + '</span>' +
                            '<span class="' + aliveClass + ' alive-indicator">' + aliveIcon + '</span>' +
                        '</div>' +
                    '</div>' +
                    '<div class="node-details">' +
                        '<div class="detail-item"><span class="detail-label">Last Seen:</span> ' + lastSeen + '</div>' +
                        '<div class="detail-item"><span class="detail-label">Connected:</span> ' + new Date(conn.connected_at).toLocaleString() + '</div>' +
                        '<div class="detail-item"><span class="detail-label">Requests:</span> ' + conn.request_count + '</div>' +
                    '</div>' +
                    '<div class="node-actions">' +
                        '<button class="btn btn-secondary show-status-btn" onclick="showNodeStatus(\'' + conn.hostname + '\', \'' + conn.ip_address + '\')">Show Status</button>' +
                        '<button class="btn btn-primary connect-btn" onclick="connectToNode(\'' + conn.hostname + '\')">Connect</button>' +
                    '</div>' +
                '</div>';
            }}).join('');

            nodesGrid.innerHTML = cardsHtml;

            // Update original cards reference for filtering
            originalCards.length = 0;
            originalCards.push(...nodesGrid.querySelectorAll('.node-card'));

            // Re-apply current search filter
            if (searchTerm) {{
                filterNodes(searchTerm);
            }}
        }}

        // Focus search input on page load
        window.addEventListener('DOMContentLoaded', function() {{
            if (searchInput.value) {{
                searchInput.focus();
            }}

            // Start automatic updates every 5 seconds
            updateStatus(); // Initial update
            updateInterval = setInterval(updateStatus, 5000);
        }});

        // Clean up interval when page unloads
        window.addEventListener('beforeunload', function() {{
            if (updateInterval) {{
                clearInterval(updateInterval);
            }}
        }});
    </script>
</body>
</html>"#,
        node_name,
        node_name,
        node_name,
        last_updated,
        total_peers,
        connected_count,
        alive_count,
        node_cards
    );

    let response = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: text/html\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {}",
        html.len(),
        html
    );

    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;

    log!("[DASHBOARD] ✓ HTTPS Dashboard served");
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