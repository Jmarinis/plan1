use std::{fs, sync::Arc};
use tokio::net::TcpListener;
use rustls::{ServerConfig, Certificate, PrivateKey};
use tokio_rustls::TlsAcceptor;
use tokio::io::{AsyncReadExt, AsyncWriteExt}; // Import the async traits

pub mod cert_manager;
pub mod peer_trust;
pub mod peer_client;
pub mod cert_verifier;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Ensure certificate exists (generate if needed)
    cert_manager::ensure_certificate()?;
    
    // Display our certificate fingerprint
    let fingerprint = cert_manager::get_cert_fingerprint()?;
    println!("Our fingerprint: {}", fingerprint);
    
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

    // Spawn HTTP listener task
    let _http_task = tokio::spawn(async move {
        loop {
            match http_listener.accept().await {
                Ok((stream, addr)) => {
                    let client_ip = addr.ip();
                    println!("\n[HTTP] New connection from {} (port: {})", client_ip, addr.port());
                    
                    tokio::spawn(async move {
                        if let Err(e) = handle_http_initial(stream, addr).await {
                            println!("[ERROR] HTTP request handling failed: {:?}", e);
                        }
                    });
                }
                Err(e) => println!("[ERROR] HTTP listener error: {:?}", e),
            }
        }
    });

    // Handle HTTPS listener in main loop
    loop {
        // Accept new HTTPS connections
        let (stream, addr) = https_listener.accept().await?;
        let client_ip = addr.ip();
        println!("\n[HTTPS] New connection from {} (port: {})", client_ip, addr.port());

        // Upgrade the TCP connection to TLS
        let acceptor = acceptor.clone();
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
                            
                            // Extract peer port from X-Peer-Port header (default 39001)
                            let peer_port = extract_peer_port(&request).unwrap_or(39001);
                            
                            // Initiate reverse connection to verify peer's certificate
                            println!("[PEER] Initiating reverse connection to {}:{}", client_ip, peer_port);
                            match peer_client::connect_to_peer(&client_ip.to_string(), peer_port, true).await {
                                Ok(_) => println!("[PEER] ✓ Mutual trust established with {}:{}", client_ip, peer_port),
                                Err(e) => {
                                    println!("[PEER] ⚠ Reverse connection failed: {}", e);
                                    println!("[PEER] Note: This is normal if {} is not running a peer server", client_ip);
                                }
                            }
                            
                            // Extract the path
                            let path = extract_path(&request).unwrap_or_else(|| "/".to_string());

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
}

async fn handle_http_initial(mut stream: tokio::net::TcpStream, addr: std::net::SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
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
    
    // Initiate reverse connection to verify peer's certificate
    println!("[PEER] Initiating reverse connection to {}:{}", client_ip, peer_port);
    let peer_verified = match peer_client::connect_to_peer(&client_ip.to_string(), peer_port, true).await {
        Ok(_) => {
            println!("[PEER] ✓ Mutual trust established with {}:{}", client_ip, peer_port);
            true
        }
        Err(e) => {
            println!("[PEER] ⚠ Reverse connection failed: {}", e);
            println!("[PEER] Note: This is normal if {} is not running a peer server", client_ip);
            false
        }
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
