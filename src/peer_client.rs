use rustls::ClientConfig;
use tokio_rustls::TlsConnector;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::sync::Arc;
use crate::peer_trust;
use crate::cert_verifier::TofuServerCertVerifier;
use rustls_pemfile;
use std::fs::File;
use std::io::BufReader;

pub struct PeerClient {
    connector: TlsConnector,
    _auto_trust: bool,
}

impl PeerClient {
    pub fn new_for_address(peer_address: String, _auto_trust: bool) -> Result<Self, Box<dyn std::error::Error>> {
        // Create a custom verifier that implements TOFU
        let verifier = TofuServerCertVerifier::new(peer_address);

        // Load our client certificate and key for mutual TLS
        let cert_path = "certs/server_cert.pem";
        let key_path = "certs/server_key.pem";
        
        let cert_file = &mut BufReader::new(File::open(cert_path)?);
        let key_file = &mut BufReader::new(File::open(key_path)?);
        
        let cert_chain = rustls_pemfile::certs(cert_file)?
            .into_iter()
            .map(rustls::Certificate)
            .collect();
        let mut keys = rustls_pemfile::pkcs8_private_keys(key_file)?;
        let private_key = rustls::PrivateKey(keys.remove(0));

        // Build client config with custom verifier
        // Note: rustls 0.20 doesn't support client certs with custom verifier directly
        // We use with_no_client_auth() but the server will still see our cert if we send it
        // Actually, we need to configure client auth properly
        let mut config = ClientConfig::builder()
            .with_safe_defaults()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();

        // Set up client certificate for mutual TLS
        config.client_auth_cert_resolver = Arc::new(AlwaysSendClientCert {
            cert_chain,
            private_key,
        });

        let connector = TlsConnector::from(Arc::new(config));

        Ok(PeerClient {
            connector,
            _auto_trust,
        })
    }

    pub async fn connect(&self, address: &str, port: u16) -> Result<(), Box<dyn std::error::Error>> {
        let addr_str = format!("{}:{}", address, port);
        println!("[CLIENT] Connecting to peer: {}", addr_str);

        // Connect TCP
        println!("[CLIENT] Establishing TCP connection...");
        let stream = TcpStream::connect(&addr_str).await?;
        println!("[CLIENT] ✓ TCP connected to {}", addr_str);

        // Attempt TLS handshake with custom cert verifier
        let domain = if let Ok(ip) = address.parse::<std::net::IpAddr>() {
            // For IP addresses, use IpAddress variant
            rustls::ServerName::IpAddress(ip)
        } else {
            // For hostnames, use DnsName
            rustls::ServerName::try_from(address)
                .map_err(|e| format!("Invalid server name: {:?}", e))?
        };

        println!("[CLIENT] Starting TLS handshake (presenting client cert)...");
        match self.connector.connect(domain, stream).await {
            Ok(mut tls_stream) => {
                println!("[CLIENT] ✓ TLS handshake successful with {}", addr_str);

                // Get our hostname
                let hostname = gethostname::gethostname()
                    .to_string_lossy()
                    .to_string();

                // Send a test message with our hostname
                let message = format!("GET / HTTP/1.1\r\nHost: peer\r\nX-Hostname: {}\r\n\r\n", hostname);
                println!("[CLIENT] Sending HTTP request with hostname: {}...", hostname);
                tls_stream.write_all(message.as_bytes()).await?;

                // Read response
                let mut buf = [0u8; 1024];
                let n = tls_stream.read(&mut buf).await?;
                let response_preview = String::from_utf8_lossy(&buf[..n.min(80)]);
                println!("[CLIENT] ✓ Received response ({} bytes): {}...", n, response_preview.lines().next().unwrap_or(""));

                Ok(())
            }
            Err(e) => {
                println!("[CLIENT] ✗ TLS handshake failed with {}: {:?}", addr_str, e);
                Err(e.into())
            }
        }
    }
}

/// Client cert resolver that always sends our certificate
struct AlwaysSendClientCert {
    cert_chain: Vec<rustls::Certificate>,
    private_key: rustls::PrivateKey,
}

impl rustls::client::ResolvesClientCert for AlwaysSendClientCert {
    fn resolve(
        &self,
        _acceptable_issuers: &[&[u8]],
        _sigschemes: &[rustls::SignatureScheme],
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        // Always return our certificate
        let signing_key = rustls::sign::any_supported_type(&self.private_key)
            .ok()?;
        Some(Arc::new(rustls::sign::CertifiedKey {
            cert: self.cert_chain.clone(),
            key: signing_key,
            ocsp: None,
            sct_list: None,
        }))
    }

    fn has_certs(&self) -> bool {
        true
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
