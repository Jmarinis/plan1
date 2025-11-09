use rustls::ClientConfig;
use tokio_rustls::TlsConnector;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::sync::Arc;
use crate::peer_trust;
use crate::cert_verifier::TofuServerCertVerifier;

pub struct PeerClient {
    connector: TlsConnector,
    _auto_trust: bool,
}

impl PeerClient {
    pub fn new_for_address(peer_address: String, _auto_trust: bool) -> Result<Self, Box<dyn std::error::Error>> {
        // Create a custom verifier that implements TOFU
        let verifier = TofuServerCertVerifier::new(peer_address);
        
        // Build client config with custom verifier
        let config = ClientConfig::builder()
            .with_safe_defaults()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        
        let connector = TlsConnector::from(Arc::new(config));
        
        Ok(PeerClient {
            connector,
            _auto_trust,
        })
    }
    
    pub async fn connect(&self, address: &str, port: u16) -> Result<(), Box<dyn std::error::Error>> {
        let addr_str = format!("{}:{}", address, port);
        println!("Connecting to peer: {}", addr_str);
        
        // Connect TCP
        let stream = TcpStream::connect(&addr_str).await?;
        
        // Attempt TLS handshake with custom cert verifier
        let domain = if let Ok(ip) = address.parse::<std::net::IpAddr>() {
            // For IP addresses, use IpAddress variant
            rustls::ServerName::IpAddress(ip)
        } else {
            // For hostnames, use DnsName
            rustls::ServerName::try_from(address)
                .map_err(|e| format!("Invalid server name: {:?}", e))?
        };
        
        match self.connector.connect(domain, stream).await {
            Ok(mut tls_stream) => {
                println!("✓ Connected to peer: {}", addr_str);
                
                // Send a test message
                let message = "GET / HTTP/1.1\r\nHost: peer\r\n\r\n";
                tls_stream.write_all(message.as_bytes()).await?;
                
                // Read response
                let mut buf = [0u8; 1024];
                let n = tls_stream.read(&mut buf).await?;
                println!("Received from peer:\n{}", String::from_utf8_lossy(&buf[..n]));
                
                Ok(())
            }
            Err(e) => {
                println!("✗ TLS handshake failed: {:?}", e);
                Err(e.into())
            }
        }
    }
}

// Helper function to connect to a peer with simple API
pub async fn connect_to_peer(address: &str, port: u16, auto_trust: bool) -> Result<(), Box<dyn std::error::Error>> {
    let peer_address = format!("{}:{}", address, port);
    let client = PeerClient::new_for_address(peer_address, auto_trust)?;
    client.connect(address, port).await
}

// List all trusted peers
pub fn list_trusted_peers() -> Result<(), Box<dyn std::error::Error>> {
    let trusted = peer_trust::TrustedPeers::load()?;
    let peers = trusted.list_peers();
    
    if peers.is_empty() {
        println!("No trusted peers yet.");
    } else {
        println!("Trusted peers:");
        for (addr, info) in peers {
            println!("  {} (fingerprint: {})", addr, &info.fingerprint[..16]);
            println!("    First seen: {}", info.first_seen);
            println!("    Last seen: {}", info.last_seen);
        }
    }
    
    Ok(())
}

// Remove a peer from trusted list
pub fn untrust_peer(address: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut trusted = peer_trust::TrustedPeers::load()?;
    trusted.remove_peer(address)?;
    println!("Removed peer from trusted list: {}", address);
    Ok(())
}
