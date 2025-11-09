// Standalone peer that runs both server and can initiate connections
// This demonstrates the full bidirectional trust negotiation

use std::{fs, sync::Arc};
use tokio::net::TcpListener;
use rustls::{ServerConfig, Certificate, PrivateKey};
use tokio_rustls::TlsAcceptor;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use plan1::{cert_manager, peer_client, peer_trust};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== P2P Peer (Server + Client) ===\n");
    
    // Parse command line arguments
    let args: Vec<String> = std::env::args().collect();
    let port: u16 = if args.len() > 1 {
        args[1].parse().unwrap_or(39002)
    } else {
        39002 // Use different port from main server
    };
    
    // Ensure certificate exists
    cert_manager::ensure_certificate()?;
    let fingerprint = cert_manager::get_cert_fingerprint()?;
    println!("Our fingerprint: {}", fingerprint);
    println!("Listening on port: {}\n", port);
    
    // Load TLS certificate and private key
    let certs = load_certs(cert_manager::get_cert_path())?;
    let key = load_private_key(cert_manager::get_key_path())?;
    
    // Configure rustls server
    let config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| e.to_string())?;
    
    let acceptor = TlsAcceptor::from(Arc::new(config));
    
    // Bind listener
    let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
    println!("✓ Server listening on port {}", port);
    println!("✓ Ready to accept connections\n");
    
    // If peer address provided as second argument, initiate connection
    if args.len() > 2 {
        let peer_addr = args[2].clone();
        let peer_port: u16 = if args.len() > 3 {
            args[3].parse().unwrap_or(39001)
        } else {
            39001
        };
        
        println!("Initiating connection to {}:{}...", peer_addr, peer_port);
        tokio::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            match peer_client::connect_to_peer(&peer_addr, peer_port, true).await {
                Ok(_) => println!("✓ Successfully connected to peer"),
                Err(e) => println!("✗ Failed to connect: {}", e),
            }
        });
    }
    
    println!("Usage:");
    println!("  peer <listen_port> [peer_ip] [peer_port]");
    println!("  Example: peer 39002 192.168.1.100 39001");
    println!("\nWaiting for connections...\n");
    
    // Accept loop
    loop {
        let (stream, addr) = listener.accept().await?;
        let client_ip = addr.ip();
        println!("New connection from {:?}", addr);
        
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            // Try to peek for HTTP vs HTTPS
            let mut peek_buf = [0u8; 5];
            let is_http = if let Ok(n) = stream.peek(&mut peek_buf).await {
                n >= 4 && peek_buf[0] != 0x16 &&
                (
                    peek_buf.starts_with(b"GET ") ||
                    peek_buf.starts_with(b"POST") ||
                    peek_buf.starts_with(b"PUT ") ||
                    peek_buf.starts_with(b"HEAD") ||
                    peek_buf.starts_with(b"DELE")
                )
            } else {
                false
            };
            
            if is_http {
                println!("Plain HTTP request from {}, use HTTPS instead", client_ip);
                return;
            }
            
            let tls_stream = acceptor.accept(stream).await;
            match tls_stream {
                Ok(mut stream) => {
                    println!("✓ TLS connection established from {}", client_ip);
                    
                    // Read request first to check for custom port header
                    let mut buf = [0u8; 1024];
                    match stream.read(&mut buf).await {
                        Ok(n) if n > 0 => {
                            // Parse request to get peer port
                            let request = String::from_utf8_lossy(&buf[..n]);
                            let peer_port = extract_peer_port(&request).unwrap_or(39001);
                            
                            // Initiate reverse connection
                            println!("Initiating reverse connection to {}:{}", client_ip, peer_port);
                            match peer_client::connect_to_peer(&client_ip.to_string(), peer_port, true).await {
                                Ok(_) => println!("✓ Mutual trust established with {}:{}", client_ip, peer_port),
                                Err(e) => println!("⚠ Reverse connection failed: {}. Continuing anyway...", e),
                            }
                            
                            println!("Received {} bytes from {}", n, client_ip);
                            
                            let response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 27\r\n\r\nHello from peer!\nTrust OK!";
                            if let Err(e) = stream.write_all(response.as_bytes()).await {
                                println!("Error writing response: {:?}", e);
                            }
                        }
                        Ok(_) => println!("Connection closed by {}", client_ip),
                        Err(e) => println!("Error reading from {}: {:?}", client_ip, e),
                    }
                }
                Err(e) => println!("TLS handshake failed from {}: {:?}", client_ip, e),
            }
        });
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

fn extract_peer_port(request: &str) -> Option<u16> {
    // Look for X-Peer-Port: header in the HTTP request
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
