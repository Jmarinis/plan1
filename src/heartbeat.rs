use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use rustls::ClientConfig;
use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::RwLock;
use crate::cert_verifier::TofuServerCertVerifier;
use plan1::ConnectionInfo;

// Macro for timestamped logging
macro_rules! log {
    ($($arg:tt)*) => {{
        let now = time::OffsetDateTime::now_utc();
        let timestamp = now.format(&time::format_description::well_known::Rfc3339).unwrap_or_else(|_| String::from("[TIME_ERROR]"));
        println!("[{}] {}", timestamp, format!($($arg)*));
    }};
}

/// Send a heartbeat request to a specific peer
pub async fn send_heartbeat_to_peer(
    peer_ip: &str,
    peer_port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    let peer_address = format!("{}:{}", peer_ip, peer_port);
    
    // Create TLS connector with TOFU verifier
    let verifier = TofuServerCertVerifier::new(peer_address.clone());
    let config = ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    
    // Connect to peer
    let stream = TcpStream::connect(&peer_address).await?;
    
    // TLS handshake
    let domain = if let Ok(ip) = peer_ip.parse::<std::net::IpAddr>() {
        rustls::ServerName::IpAddress(ip)
    } else {
        rustls::ServerName::try_from(peer_ip)
            .map_err(|e| format!("Invalid server name: {:?}", e))?
    };
    
    let mut tls_stream = connector.connect(domain, stream).await?;
    
    // Get our hostname
    let hostname = gethostname::gethostname()
        .to_string_lossy()
        .to_string();
    
    // Send heartbeat request
    let message = format!(
        "GET /heartbeat HTTP/1.1\r\nHost: peer\r\nX-Hostname: {}\r\n\r\n",
        hostname
    );
    tls_stream.write_all(message.as_bytes()).await?;
    
    // Read response (with timeout)
    let mut buf = [0u8; 512];
    let n = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tls_stream.read(&mut buf)
    ).await??;
    
    if n > 0 {
        let response = String::from_utf8_lossy(&buf[..n]);
        if response.contains("200 OK") {
            Ok(())
        } else {
            Err(format!("Unexpected response: {}", response.lines().next().unwrap_or("")).into())
        }
    } else {
        Err("No response received".into())
    }
}

/// Send heartbeats to all verified peers and update connection tracking
pub(crate) async fn send_heartbeats_to_all(
    connections: &Arc<RwLock<HashMap<String, ConnectionInfo>>>,
) {
    let peers_to_check: Vec<(String, String)> = {
        let conns = connections.read().await;
        conns.iter()
            .filter(|(_, info)| info.verified)
            .map(|(key, info)| (key.clone(), info.ip_address.clone()))
            .collect()
    };
    
    if peers_to_check.is_empty() {
        return;
    }
    
    log!("[HEARTBEAT] Sending heartbeats to {} peers", peers_to_check.len());
    
    for (peer_key, ip_str) in peers_to_check {
        // Parse peer address to get port
        let parts: Vec<&str> = peer_key.split(':').collect();
        if parts.len() != 2 {
            continue;
        }
        
        let port = match parts[1].parse::<u16>() {
            Ok(p) => p,
            Err(_) => continue,
        };
        
        // Update last_heartbeat_sent timestamp
        let now = time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| String::from("unknown"));
        
        {
            let mut conns = connections.write().await;
            if let Some(info) = conns.get_mut(&peer_key) {
                info.last_heartbeat_sent = Some(now.clone());
            }
        }
        
        // Send heartbeat
        let heartbeat_success = match send_heartbeat_to_peer(&ip_str, port).await {
            Ok(_) => {
                log!("[HEARTBEAT] ✓ Peer {} is alive", peer_key);
                true
            }
            Err(e) => {
                log!("[HEARTBEAT] ✗ Peer {} did not respond: {}", peer_key, e);
                false
            }
        };
        
        // Update connection info
        let mut conns = connections.write().await;
        if let Some(info) = conns.get_mut(&peer_key) {
            if heartbeat_success {
                info.last_heartbeat_received = Some(now.clone());
                info.alive = true;
                info.status = "Connected".to_string();
            } else {
                info.alive = false;
                info.status = "Unresponsive".to_string();
            }
        }
    }
    
    log!("[HEARTBEAT] Heartbeat round complete");
}

/// Start the background heartbeat task
pub(crate) fn start_heartbeat_task(
    connections: Arc<RwLock<HashMap<String, ConnectionInfo>>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        log!("[HEARTBEAT] Starting heartbeat task (60 second interval)");
        
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        
        loop {
            interval.tick().await;
            send_heartbeats_to_all(&connections).await;
        }
    })
}
