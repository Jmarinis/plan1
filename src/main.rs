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

#[derive(Debug, Clone, Serialize)]
struct ConnectionInfo {
    peer: String,
    connected_at: String,
    request_count: usize,
    verified: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Ensure certificate exists (generate if needed)
    cert_manager::ensure_certificate()?;
    
    // Display our certificate fingerprint
    let fingerprint = cert_manager::get_cert_fingerprint()?;
    println!("Our fingerprint: {}", fingerprint);
    
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

    // Bind HTTP listener on port 39000 (for initial requests)
    let http_listener = TcpListener::bind("0.0.0.0:39000").await?;
    println!("HTTP server listening on port 39000 (initial requests only)");
    
    // Bind HTTPS listener on port 39001 (for secure communication)
    let https_listener = TcpListener::bind("0.0.0.0:39001").await?;
    println!("HTTPS server listening on port 39001 (all subsequent requests)");
    println!("\nPress Ctrl-C to shutdown gracefully\n");

    // Setup Ctrl-C handler
    let shutdown = Arc::new(tokio::sync::Notify::new());
    let shutdown_clone = shutdown.clone();
    
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.expect("Failed to listen for Ctrl-C");
        println!("\n\n[SHUTDOWN] Received Ctrl-C, shutting down gracefully...");
        shutdown_clone.notify_waiters();
    });

    // Spawn HTTP listener task
    let verified_peers_http = verified_peers.clone();
    let shutdown_http = shutdown.clone();
    let _http_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                result = http_listener.accept() => {
                    match result {
                        Ok((stream, addr)) => {
                            let client_ip = addr.ip();
                            println!("\n[HTTP] New connection from {} (port: {})", client_ip, addr.port());
                            
                            let verified_peers_clone = verified_peers_http.clone();
                            tokio::spawn(async move {
                                if let Err(e) = handle_http_initial(stream, addr, verified_peers_clone).await {
                                    println!("[ERROR] HTTP request handling failed: {:?}", e);
                                }
                            });
                        }
                        Err(e) => println!("[ERROR] HTTP listener error: {:?}", e),
                    }
                }
                _ = shutdown_http.notified() => {
                    println!("[SHUTDOWN] HTTP listener shutting down");
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
        println!("\n[HTTPS] New connection from {} (port: {})", client_ip, addr.port());

        // Upgrade the TCP connection to TLS
        let acceptor = acceptor.clone();
        let connections_clone = connections.clone();
        let verified_peers_https = verified_peers.clone();
        tokio::spawn(async move {
            println!("[TLS] Starting TLS handshake with {}", client_ip);

            let tls_stream = acceptor.accept(stream).await;
            match tls_stream {
                Ok(mut stream) => {
                    println!("[TLS] ✓ Handshake successful with {}", client_ip);
                    
                    // Read the request first to check for custom port header
                    let mut buf = [0u8; 1024];
                    match stream.read(&mut buf).await {
                Ok(n) if n > 0 => {
                            // Parse the HTTP request
                            let request = String::from_utf8_lossy(&buf[..n]);
                            let first_line = request.lines().next().unwrap_or("<empty>");
                            println!("[HTTP] Request from {}: {}", client_ip, first_line);
                            
                            // Extract the path
                            let path = extract_path(&request).unwrap_or_else(|| "/".to_string());
                            
                            // Handle /monitor endpoint (localhost only)
                            if path == "/monitor" {
                                if is_localhost(&client_ip) {
                                    if let Err(e) = handle_monitor_request(&mut stream, &connections_clone).await {
                                        println!("[ERROR] Monitor request failed: {:?}", e);
                                    }
                                } else {
                                    println!("[MONITOR] Rejected non-localhost request from {}", client_ip);
                                    let response = "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: 36\r\n\r\nMonitor endpoint only for localhost";
                                    let _ = stream.write_all(response.as_bytes()).await;
                                }
                                return;
                            }
                            
                            // Extract peer port from X-Peer-Port header (default 39001)
                            let peer_port = extract_peer_port(&request).unwrap_or(39001);
                            let peer_key = format!("{}:{}", client_ip, peer_port);
                            
                            // Check if peer is already verified
                            let already_verified = {
                                let peers = verified_peers_https.read().await;
                                peers.contains(&peer_key)
                            };
                            
                            let peer_verified = if already_verified {
                                println!("[PEER] Peer {} already verified, skipping certificate exchange", peer_key);
                                true
                            } else {
                                // Add to verified peers BEFORE initiating connection to prevent infinite loop
                                {
                                    let mut peers = verified_peers_https.write().await;
                                    peers.insert(peer_key.clone());
                                }
                                
                                // Initiate reverse connection to verify peer's certificate
                                println!("[PEER] Initiating reverse connection to {}", peer_key);
                                let connection_succeeded = match peer_client::connect_to_peer(&client_ip.to_string(), peer_port, true).await {
                                    Ok(_) => {
                                        println!("[PEER] ✓ Mutual trust established with {}", peer_key);
                                        true
                                    }
                                    Err(e) => {
                                        println!("[PEER] ⚠ Reverse connection failed: {}", e.to_string());
                                        println!("[PEER] Note: This is normal if {} is not running a peer server", client_ip);
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
                                let mut conns = connections_clone.write().await;
                                conns.entry(peer_key.clone())
                                    .and_modify(|info| info.request_count += 1)
                                    .or_insert_with(|| {
                                        let now = std::time::SystemTime::now()
                                            .duration_since(std::time::UNIX_EPOCH)
                                            .unwrap()
                                            .as_secs();
                                        ConnectionInfo {
                                            peer: peer_key.clone(),
                                            connected_at: now.to_string(),
                                            request_count: 1,
                                            verified: peer_verified,
                                        }
                                    });
                            }

                            // Build response with the path
                            let body = format!("Hello, World! Path: {}", path);
                            let response = format!("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}", body.len(), body);
                            println!("[HTTP] Sending 200 OK response for path: {}", path);
                            if let Err(e) = stream.write_all(response.as_bytes()).await {
                                println!("[ERROR] Failed to write response: {:?}", e);
                            } else {
                                println!("[HTTP] ✓ Response sent successfully to {}", client_ip);
                            }
                        }
                        Ok(_) => println!("[CONN] Connection closed by {}", client_ip),
                        Err(e) => println!("[ERROR] Read error from {}: {:?}", client_ip, e),
                    }
                }
                Err(e) => {
                    println!("[TLS] ✗ Handshake failed with {}: {:?}", client_ip, e);
                    println!("[TLS] Common causes:");
                    println!("[TLS]   - Browser rejecting self-signed certificate (accept security warning)");
                    println!("[TLS]   - Client doesn't have TOFU verifier (use Rust peer client)");
                    println!("[TLS]   - Certificate mismatch");
                },
            }
        });
            }
            _ = shutdown.notified() => {
                println!("[SHUTDOWN] HTTPS listener shutting down");
                break;
            }
        }
    }
    
    println!("[SHUTDOWN] Server stopped. Goodbye!");
    Ok(())
}

async fn handle_http_initial(
    mut stream: tokio::net::TcpStream,
    addr: std::net::SocketAddr,
    verified_peers: Arc<RwLock<HashSet<String>>>,
) -> Result<(), Box<dyn std::error::Error>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    
    let client_ip = addr.ip();
    
    // Read the HTTP request
    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }
    
    let request = String::from_utf8_lossy(&buf[..n]);
    let first_line = request.lines().next().unwrap_or("<empty>");
    println!("[HTTP] Request from {}: {}", client_ip, first_line);
    
    let path = extract_path(&request).unwrap_or_else(|| "/".to_string());
    
    // Get the host from the request or use the server's IP
    let host = extract_host(&request).unwrap_or_else(|| {
        addr.ip().to_string()
    });
    
    // Extract peer port from X-Peer-Port header (default 39001)
    let peer_port = extract_peer_port(&request).unwrap_or(39001);
    
    // Create peer key for tracking
    let peer_key = format!("{}:{}", client_ip, peer_port);
    
    // Check if peer is already verified
    let already_verified = {
        let peers = verified_peers.read().await;
        peers.contains(&peer_key)
    };
    
    let peer_verified = if already_verified {
        println!("[PEER] Peer {} already verified, skipping certificate exchange", peer_key);
        true
    } else {
        // Add to verified peers BEFORE initiating connection to prevent infinite loop
        {
            let mut peers = verified_peers.write().await;
            peers.insert(peer_key.clone());
        }
        
        // Initiate reverse connection to verify peer's certificate
        println!("[PEER] Initiating reverse connection to {}", peer_key);
        let connection_succeeded = match peer_client::connect_to_peer(&client_ip.to_string(), peer_port, true).await {
            Ok(_) => {
                println!("[PEER] ✓ Mutual trust established with {}", peer_key);
                true
            }
            Err(e) => {
                println!("[PEER] ⚠ Reverse connection failed: {}", e.to_string());
                println!("[PEER] Note: This is normal if {} is not running a peer server", client_ip);
                false
            }
        };
        
        // Remove from verified peers if connection failed
        if !connection_succeeded {
            let mut peers = verified_peers.write().await;
            peers.remove(&peer_key);
        }
        
        connection_succeeded
    };
    
    // Get our certificate fingerprint
    let fingerprint = cert_manager::get_cert_fingerprint()?;
    
    // Build HTTPS URL for future requests
    let https_url = format!("https://{}:39001", host);
    
    // Build JSON response with initial data and HTTPS upgrade information
    let body = serde_json::json!({
        "message": "Initial connection successful",
        "path": path,
        "https_endpoint": https_url,
        "server_fingerprint": fingerprint,
        "peer_verified": peer_verified,
        "note": "Future requests should use HTTPS"
    });
    let body_str = body.to_string();
    
    // Send 200 OK with upgrade information
    let response = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         X-HTTPS-Endpoint: {}\r\n\
         X-Server-Fingerprint: {}\r\n\
         X-Peer-Verified: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {}",
        body_str.len(),
        https_url,
        fingerprint,
        peer_verified,
        body_str
    );
    
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;
    
    println!("[HTTP] ✓ Initial request served, client should upgrade to HTTPS: {}", https_url);
    Ok(())
}

fn extract_host(request: &str) -> Option<String> {
    // Look for Host: header in the HTTP request
    for line in request.lines() {
        if line.to_lowercase().starts_with("host:") {
            let host = line[5..].trim();
            // Remove port if present and return just hostname/IP
            return Some(host.split(':').next()?.to_string());
        }
    }
    None
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
    
    println!("[MONITOR] Serving monitor request");
    
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
    
    println!("[MONITOR] ✓ Monitor data sent");
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
