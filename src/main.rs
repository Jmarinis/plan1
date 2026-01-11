#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(dead_code)]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use std::sync::Arc;
use tokio::sync::{Notify, Mutex};
use std::collections::HashMap;
use std::net::SocketAddr;
use plan1::config;
use plan1::cert_manager;
use rustls_pemfile;
use rustls;
use tokio::signal;
use std::io;

// Assuming these are defined elsewhere or need to be stubbed for compilation
type PeerKey = String;
type PeerInfo = String; // Placeholder

macro_rules! log {
    ($($arg:tt)*) => {{
        let now = time::OffsetDateTime::now_utc();
        println!("[{}] {}", now.format(&time::format_description::parse("[hour]:[minute]:[second]").unwrap()).unwrap(), format!($($arg)*));
    }};
}

// Dashboard HTML content
const DASHBOARD_HTML: &str = include_str!("../dashboard.html");

// Handle dashboard HTTP requests
async fn handle_dashboard_request(
    mut stream: TcpStream,
    client_ip: std::net::IpAddr,
) -> Result<(), Box<dyn std::error::Error>> {
    log!("[DASHBOARD] Handling HTTP connection from {}", client_ip);

    // Read the HTTP request (just the first line to keep it simple)
    let mut buffer = [0; 1024];
    let _ = stream.read(&mut buffer).await;

    // Build HTTP response with dashboard HTML
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{}",
        DASHBOARD_HTML.len(),
        DASHBOARD_HTML
    );

    stream.write_all(response.as_bytes()).await?;
    Ok(())
}

// Placeholder for handle_connection_request function
async fn handle_connection_request(
    stream: TcpStream,
    client_ip: std::net::IpAddr,
    config: &crate::config::Config,
) -> Result<(), Box<dyn std::error::Error>> {
    log!("[HTTP] Handling plain HTTP connection from {}", client_ip);
    // In a real implementation, you'd process the HTTP request here.
    // For now, just close the stream.
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // --- Mock/Placeholder Initializations (These would typically come from other modules) ---
    let shutdown = Arc::new(Notify::new());
    let config = Arc::new(plan1::config::Config::load().unwrap());

    // Ensure certificates exist and load them
    plan1::cert_manager::ensure_certificate()?;
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

    let acceptor = Arc::new(
        tokio_rustls::TlsAcceptor::from(
            Arc::new(
                rustls::ServerConfig::builder()
                    .with_safe_defaults()
                    .with_no_client_auth()
                    .with_single_cert(cert_chain, private_key)
                    .unwrap(),
            ),
        ),
    );
    let verified_peers: Arc<Mutex<HashMap<PeerKey, PeerInfo>>> = Arc::new(Mutex::new(HashMap::new()));
    let connections: Arc<Mutex<HashMap<SocketAddr, TcpStream>>> = Arc::new(Mutex::new(HashMap::new()));

    let connection_listener = TcpListener::bind(format!("0.0.0.0:{}", config.network.connection_port)).await?;
    let dashboard_listener = TcpListener::bind(format!("0.0.0.0:{}", config.network.dashboard_port)).await?;
    // --- End Mock Initializations ---

    // Spawn connection listener task
    let shutdown_connection = shutdown.clone();
    let config_connection = config.clone();
    let acceptor_connection = acceptor.clone();
    let verified_peers_connection = verified_peers.clone();
    let connections_connection = connections.clone();
    let _connection_task = tokio::spawn(async move {
        log!("[CONNECTION] Connection listener task started");
        loop {
            tokio::select! {
                result = connection_listener.accept() => {
                    match result {
                        Ok((stream, addr)) => {
                            let client_ip = addr.ip();
                            log!("[CONNECTION] New connection from {}:{}", client_ip, addr.port());

                            // Clone config before spawning async task
                            let config_clone = config_connection.clone();
                            let acceptor_for_task = acceptor_connection.clone();
                            tokio::spawn(async move {
                                // Peek to determine if this is a TLS or plain HTTP connection
                                let mut peek_buf = [0u8; 5];
                                let is_tls = if let Ok(n) = stream.peek(&mut peek_buf).await {
                                    n >= 1 && peek_buf[0] == 0x16 // TLS handshake starts with 0x16
                                } else {
                                    false
                                };

                                if is_tls {
                                    log!("[PEER] TLS connection detected from {}", client_ip);
                                    // Handle TLS peer connection
                                    let acceptor = acceptor_for_task.clone();
                                    let tls_stream = acceptor.accept(stream).await;
                                    match tls_stream {
                                        Ok(mut stream) => {
                                            log!("[TLS] ✓ TLS handshake successful with {}", client_ip);

                                            // Read the request first to check for custom port header
                                            let mut buf = [0u8; 1024];
                                            match stream.read(&mut buf).await {
                                                Ok(n) if n > 0 => {
                                                    let request = String::from_utf8_lossy(&buf[..n]);
                                                    log!("[PEER] Received {} bytes from {}: {:?}", n, client_ip, &request[..50.min(request.len())]);

                                                    // Build response
                                                    let response = format!("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nOK");
                                                    if let Err(e) = stream.write_all(response.as_bytes()).await {
                                                        log!("[ERROR] Failed to write TLS response: {:?}", e);
                                                    } else {
                                                        log!("[PEER] ✓ TLS response sent successfully to {}", client_ip);
                                                    }
                                                }
                                                Ok(_) => log!("[PEER] Connection closed by {}", client_ip),
                                                Err(e) => log!("[ERROR] Read error from {}: {:?}", client_ip, e),
                                            }
                                        }
                                        Err(e) => {
                                            log!("[TLS] ✗ TLS handshake failed with {}: {:?}", client_ip, e);
                                        },
                                    }
                                } else {
                                    log!("[HTTP] Plain HTTP connection from {}", client_ip);
                                    // Handle as plain HTTP connection request
                                    if let Err(e) = handle_connection_request(stream, client_ip, &config_clone).await {
                                        log!("[ERROR] Connection request failed: {:?}", e);
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
    let _dashboard_task = tokio::spawn(async move {
        log!("[DASHBOARD] Dashboard listener task started on port {}", config.network.dashboard_port);
        loop {
            tokio::select! {
                result = dashboard_listener.accept() => {
                    match result {
                        Ok((stream, addr)) => {
                            let client_ip = addr.ip();
                            tokio::spawn(async move {
                                if let Err(e) = handle_dashboard_request(stream, client_ip).await {
                                    log!("[ERROR] Dashboard request failed: {:?}", e);
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

    // Set up Ctrl+C signal handler
    let shutdown_for_signal = shutdown.clone();
    tokio::spawn(async move {
        if let Err(e) = signal::ctrl_c().await {
            log!("[ERROR] Failed to listen for Ctrl+C: {:?}", e);
        } else {
            log!("[SHUTDOWN] Received Ctrl+C signal");
            shutdown_for_signal.notify_one();
        }
    });

    // Wait for a shutdown signal (e.g., from another task or OS signal)
    shutdown.notified().await;
    log!("[SHUTDOWN] Main application shutting down.");

    Ok(())
}
