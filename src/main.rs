use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use std::sync::Arc;
use tokio::sync::{Notify, RwLock};
use std::collections::HashMap;
use std::net::SocketAddr;
use plan1::config;
use plan1::cert_manager;
use plan1::peer_trust;
use plan1::peer_client;
use plan1::{ConnectionInfo, peer_trust::TrustedPeers};
use rustls_pemfile;
use rustls;
use tokio::signal;
use sha2::{Digest, Sha256};

macro_rules! log {
    ($($arg:tt)*) => {{
        let now = time::OffsetDateTime::now_utc();
        println!("[{}] {}", now.format(&time::format_description::parse("[hour]:[minute]:[second]").unwrap()).unwrap(), format!($($arg)*));
    }};
}

// Dashboard HTML content
const DASHBOARD_HTML: &str = include_str!("../dashboard.html");

// Get our own certificate fingerprint
fn get_own_fingerprint() -> Result<String, Box<dyn std::error::Error>> {
    let config = config::Config::load()?;
    let cert_path = &config.security.cert_path;
    let cert_file = &mut std::io::BufReader::new(std::fs::File::open(cert_path)?);
    let cert_chain = rustls_pemfile::certs(cert_file)?;
    
    if let Some(cert_der) = cert_chain.first() {
        let mut hasher = Sha256::new();
        hasher.update(cert_der);
        Ok(hex::encode(hasher.finalize()))
    } else {
        Err("No certificate found".into())
    }
}

// Handle dashboard HTTP requests
async fn handle_dashboard_request(
    mut stream: TcpStream,
    client_ip: std::net::IpAddr,
    connections: Arc<RwLock<HashMap<String, ConnectionInfo>>>,
) -> Result<(), Box<dyn std::error::Error>> {
    log!("[DASHBOARD] Handling HTTP connection from {}", client_ip);

    // Read the HTTP request
    let mut buffer = [0; 1024];
    let n = stream.read(&mut buffer).await?;
    let request = String::from_utf8_lossy(&buffer[..n]);
    
    // Parse path for API endpoints
    let mut html = DASHBOARD_HTML.to_string();
    
    // Simple API: /api/peers returns JSON
    if request.starts_with("GET /api/peers") {
        let conns = connections.read().await;
        let peers_json: Vec<_> = conns.values().collect();
        let json = serde_json::to_string_pretty(&peers_json)?;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            json.len(),
            json
        );
        stream.write_all(response.as_bytes()).await?;
        return Ok(());
    }
    
    // Serve dashboard HTML
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{}",
        html.len(),
        html
    );

    stream.write_all(response.as_bytes()).await?;
    Ok(())
}

// Handle plain HTTP connection - redirect to HTTPS
async fn handle_http_redirect(
    mut stream: TcpStream,
    client_ip: std::net::IpAddr,
    https_port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    log!("[HTTP] Received plain HTTP from {}, redirecting to HTTPS", client_ip);

    // Read the HTTP request to get the path
    let mut buffer = [0; 1024];
    let n = stream.read(&mut buffer).await?;
    let request = String::from_utf8_lossy(&buffer[..n]);
    
    // Extract path from request
    let path = request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/");
    
    // Send redirect response
    let response = format!(
        "HTTP/1.1 301 Moved Permanently\r\nLocation: https://{}:{}{}\r\nContent-Length: 0\r\n\r\n",
        client_ip, https_port, path
    );
    
    stream.write_all(response.as_bytes()).await?;
    Ok(())
}

// Handle incoming TLS peer connection with TOFU verification
async fn handle_peer_connection(
    stream: TcpStream,
    client_addr: SocketAddr,
    config: Arc<config::Config>,
    verified_peers: Arc<RwLock<HashMap<String, PeerRecord>>>,
    connections: Arc<RwLock<HashMap<String, ConnectionInfo>>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let client_ip = client_addr.ip();
    let client_port = client_addr.port();
    
    log!("[PEER] Handling TLS connection from {}:{}", client_ip, client_port);
    
    // Load our certificate and key
    let cert_path = &config.security.cert_path;
    let key_path = &config.security.key_path;
    
    let cert_file = &mut std::io::BufReader::new(std::fs::File::open(cert_path)?);
    let key_file = &mut std::io::BufReader::new(std::fs::File::open(key_path)?);
    
    let cert_chain = rustls_pemfile::certs(cert_file)?
        .into_iter()
        .map(rustls::Certificate)
        .collect();
    let mut keys = rustls_pemfile::pkcs8_private_keys(key_file)?;
    let private_key = rustls::PrivateKey(keys.remove(0));
    
    // Create server config with client cert verifier that accepts any cert
    // (we'll verify via TOFU after receiving their certificate)
    let server_config = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)?;
    
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
    
    // Perform TLS handshake
    let mut tls_stream = acceptor.accept(stream).await?;
    log!("[TLS] ✓ TLS handshake successful with {}", client_ip);
    
    // Read the incoming request to get peer's hostname
    let mut buf = [0u8; 2048];
    let n = tls_stream.read(&mut buf).await?;
    
    if n == 0 {
        log!("[PEER] Connection closed by {} immediately", client_ip);
        return Ok(());
    }
    
    let request = String::from_utf8_lossy(&buf[..n]);
    log!("[PEER] Received request from {}: {} bytes", client_ip, n);
    
    // Extract hostname from X-Hostname header if present
    let peer_hostname = request
        .lines()
        .find(|line| line.to_lowercase().starts_with("x-hostname:"))
        .and_then(|line| line.split(':').nth(1))
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| format!("peer-{}", client_ip));
    
    // Extract peer port from X-Peer-Port header (for bidirectional connection)
    let peer_port = request
        .lines()
        .find(|line| line.to_lowercase().starts_with("x-peer-port:"))
        .and_then(|line| line.split(':').nth(1))
        .and_then(|s| s.trim().parse::<u16>().ok())
        .unwrap_or(config.network.connection_port);
    
    log!("[PEER] Peer {} hostname: {}, port: {}", client_ip, peer_hostname, peer_port);
    
    // Get peer's certificate fingerprint from the TLS connection
    let peer_cert = tls_stream.get_ref().1.peer_certificates()
        .and_then(|certs| certs.first())
        .map(|cert| cert.0.as_slice());
    
    let peer_fingerprint = if let Some(cert_der) = peer_cert {
        let mut hasher = Sha256::new();
        hasher.update(cert_der);
        hex::encode(hasher.finalize())
    } else {
        log!("[PEER] No certificate presented by {}", client_ip);
        return Ok(());
    };
    
    log!("[PEER] Peer {} fingerprint: {}...", client_ip, &peer_fingerprint[..16]);
    
    // Verify peer certificate using TOFU
    let peer_key = format!("{}:{}", client_ip, peer_port);
    let peer_trusted = match peer_trust::verify_peer_certificate(
        &peer_key,
        &hex::decode(&peer_fingerprint).unwrap(),
        true, // auto_trust
        Some(peer_hostname.clone()),
    ) {
        Ok(verified) => verified,
        Err(e) => {
            log!("[PEER] Certificate verification failed for {}: {}", client_ip, e);
            false
        }
    };
    
    if !peer_trusted {
        log!("[PEER] Rejecting untrusted peer {}", client_ip);
        return Ok(());
    }
    
    // Update connections tracking
    let now = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| String::from("unknown"));
    
    {
        let mut conns = connections.write().await;
        conns.entry(peer_key.clone())
            .and_modify(|info| {
                info.last_message_time = now.clone();
                info.alive = true;
                info.status = "Connected".to_string();
            })
            .or_insert_with(|| ConnectionInfo {
                hostname: peer_hostname.clone(),
                ip_address: client_ip.to_string(),
                status: "Connected".to_string(),
                connected_at: now.clone(),
                last_message: "Initial connection".to_string(),
                last_message_time: now.clone(),
                request_count: 0,
                verified: true,
                last_heartbeat_sent: None,
                last_heartbeat_received: None,
                alive: true,
            });
    }
    
    // Send response with our hostname and port for bidirectional trust
    let our_hostname = gethostname::gethostname()
        .to_string_lossy()
        .to_string();
    
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nX-Hostname: {}\r\nX-Peer-Port: {}\r\nContent-Length: 2\r\n\r\nOK",
        our_hostname,
        config.network.connection_port
    );
    tls_stream.write_all(response.as_bytes()).await?;
    log!("[PEER] ✓ Response sent to {}", client_ip);
    
    // Initiate reverse connection for bidirectional trust
    log!("[PEER] Initiating reverse connection to {}:{} to establish mutual trust", client_ip, peer_port);
    
    let reverse_result = peer_client::connect_to_peer(&client_ip.to_string(), peer_port, true).await;
    
    match reverse_result {
        Ok(_) => {
            log!("[PEER] ✓ Bidirectional trust established with {} ({})", peer_key, peer_hostname);
        }
        Err(e) => {
            log!("[PEER] ⚠ Reverse connection to {} failed: {} (continuing anyway)", peer_key, e);
        }
    }
    
    // Keep connection alive for potential future messages
    // In a full implementation, you'd have a message loop here
    log!("[PEER] Connection with {} established successfully", peer_key);
    
    Ok(())
}

#[derive(Debug, Clone)]
struct PeerRecord {
    fingerprint: String,
    hostname: String,
    ip: String,
    port: u16,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    log!("=== Plan1 P2P Node Starting ===");
    
    let shutdown = Arc::new(Notify::new());
    let config = Arc::new(config::Config::load()?);
    
    // Ensure certificates exist
    cert_manager::ensure_certificate()?;
    
    // Display our fingerprint
    if let Ok(our_fingerprint) = get_own_fingerprint() {
        log!("[CERT] Our fingerprint: {}...", &our_fingerprint[..16]);
    }
    
    // Shared state
    let verified_peers: Arc<RwLock<HashMap<String, PeerRecord>>> = Arc::new(RwLock::new(HashMap::new()));
    let connections: Arc<RwLock<HashMap<String, ConnectionInfo>>> = Arc::new(RwLock::new(HashMap::new()));
    
    // Load existing trusted peers count (but don't display offline peers)
    {
        let trusted = TrustedPeers::load()?;
        let peer_count = trusted.list_peers().len();
        if peer_count > 0 {
            log!("[PEERS] {} trusted peers in storage (will appear when they connect)", peer_count);
        }
    }
    
    // Bind listeners
    let bind_addr = if config.network.bind_host.is_empty() {
        "0.0.0.0".to_string()
    } else {
        config.network.bind_host.clone()
    };
    
    let connection_listener = TcpListener::bind(format!(
        "{}:{}",
        bind_addr, config.network.connection_port
    )).await?;
    
    let dashboard_listener = TcpListener::bind(format!(
        "{}:{}",
        bind_addr, config.network.dashboard_port
    )).await?;
    
    log!("[LISTENER] Connection listener on port {}", config.network.connection_port);
    log!("[LISTENER] Dashboard listener on port {}", config.network.dashboard_port);
    
    // Spawn connection listener task
    let shutdown_connection = shutdown.clone();
    let config_conn = config.clone();
    let verified_peers_conn = verified_peers.clone();
    let connections_conn = connections.clone();
    
    let _connection_task = tokio::spawn(async move {
        log!("[CONNECTION] Connection listener task started");
        loop {
            tokio::select! {
                result = connection_listener.accept() => {
                    match result {
                        Ok((stream, addr)) => {
                            let client_ip = addr.ip();
                            log!("[CONNECTION] New connection from {}:{}", client_ip, addr.port());
                            
                            let config_clone = config_conn.clone();
                            let verified_peers_clone = verified_peers_conn.clone();
                            let connections_clone = connections_conn.clone();
                            
                            tokio::spawn(async move {
                                // Peek to determine if TLS or plain HTTP
                                let mut peek_buf = [0u8; 5];
                                let is_tls = if let Ok(n) = stream.peek(&mut peek_buf).await {
                                    n >= 1 && peek_buf[0] == 0x16
                                } else {
                                    false
                                };
                                
                                if is_tls {
                                    if let Err(e) = handle_peer_connection(
                                        stream,
                                        addr,
                                        config_clone,
                                        verified_peers_clone,
                                        connections_clone,
                                    ).await {
                                        log!("[ERROR] Peer connection handler error: {:?}", e);
                                    }
                                } else {
                                    // Plain HTTP - redirect to HTTPS
                                    if let Err(e) = handle_http_redirect(
                                        stream,
                                        client_ip,
                                        config_clone.network.connection_port,
                                    ).await {
                                        log!("[ERROR] HTTP redirect error: {:?}", e);
                                    }
                                }
                            });
                        }
                        Err(e) => log!("[ERROR] Connection listener error: {:?}", e),
                    }
                }
                _ = shutdown_connection.notified() => {
                    log!("[SHUTDOWN] Connection listener shutting down");
                    break;
                }
            }
        }
    });
    
    // Spawn dashboard listener task
    let shutdown_dashboard = shutdown.clone();
    let connections_dashboard = connections.clone();
    
    let _dashboard_task = tokio::spawn(async move {
        log!("[DASHBOARD] Dashboard listener task started");
        loop {
            tokio::select! {
                result = dashboard_listener.accept() => {
                    match result {
                        Ok((stream, addr)) => {
                            let client_ip = addr.ip();
                            let connections_clone = connections_dashboard.clone();
                            
                            tokio::spawn(async move {
                                if let Err(e) = handle_dashboard_request(
                                    stream,
                                    client_ip,
                                    connections_clone,
                                ).await {
                                    log!("[ERROR] Dashboard request error: {:?}", e);
                                }
                            });
                        }
                        Err(e) => log!("[ERROR] Dashboard listener error: {:?}", e),
                    }
                }
                _ = shutdown_dashboard.notified() => {
                    log!("[SHUTDOWN] Dashboard listener shutting down");
                    break;
                }
            }
        }
    });
    
    // Spawn broadcast sender (send discovery message every 30 seconds)
    let shutdown_broadcast = shutdown.clone();
    let broadcast_port = config.network.connection_port;
    
    let _broadcast_task = tokio::spawn(async move {
        log!("[BROADCAST] Starting broadcast discovery (sending every 30s)");
        
        // Send initial broadcast
        if let Err(e) = plan1::broadcast::send_broadcast(broadcast_port).await {
            log!("[BROADCAST] Initial broadcast failed: {}", e);
        }
        
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if let Err(e) = plan1::broadcast::send_broadcast(broadcast_port).await {
                        log!("[BROADCAST] Broadcast failed: {}", e);
                    }
                }
                _ = shutdown_broadcast.notified() => {
                    log!("[SHUTDOWN] Broadcast sender shutting down");
                    break;
                }
            }
        }
    });
    
    // Spawn broadcast listener
    let shutdown_listener = shutdown.clone();
    let verified_peers_listener: Arc<RwLock<HashMap<String, String>>> = Arc::new(RwLock::new(HashMap::new()));
    let connections_listener = connections.clone();
    let broadcast_port = config.network.connection_port;
    
    let _listener_task = tokio::spawn(async move {
        log!("[BROADCAST] Starting broadcast listener on port {}", broadcast_port);
        
        if let Err(e) = plan1::broadcast::start_broadcast_listener(
            verified_peers_listener,
            connections_listener,
            broadcast_port,
        ).await {
            log!("[BROADCAST] Broadcast listener error: {}", e);
        }
    });
    
    // Spawn heartbeat task
    let shutdown_heartbeat = shutdown.clone();
    let connections_heartbeat = connections.clone();
    
    let _heartbeat_task = tokio::spawn(async move {
        log!("[HEARTBEAT] Starting heartbeat monitoring (every 60s)");
        
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    plan1::heartbeat::send_heartbeats_to_all(&connections_heartbeat).await;
                }
                _ = shutdown_heartbeat.notified() => {
                    log!("[SHUTDOWN] Heartbeat task shutting down");
                    break;
                }
            }
        }
    });
    
    // Set up Ctrl+C signal handler
    let shutdown_signal = shutdown.clone();
    tokio::spawn(async move {
        if let Err(e) = signal::ctrl_c().await {
            log!("[ERROR] Failed to listen for Ctrl+C: {:?}", e);
        } else {
            log!("[SHUTDOWN] Received Ctrl+C signal");
            shutdown_signal.notify_one();
        }
    });
    
    log!("=== Plan1 P2P Node Ready ===");
    log!("Dashboard: http://localhost:{}", config.network.dashboard_port);
    log!("Peer connections: port {}", config.network.connection_port);
    
    // Wait for shutdown signal
    shutdown.notified().await;
    log!("[SHUTDOWN] Main application shutting down");
    
    Ok(())
}
