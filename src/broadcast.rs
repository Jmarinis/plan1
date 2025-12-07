use tokio::net::UdpSocket;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::sync::RwLock;
use std::collections::HashMap;
use crate::ConnectionInfo;

// Macro for timestamped logging
macro_rules! log {
    ($($arg:tt)*) => {{
        let now = time::OffsetDateTime::now_utc();
        let timestamp = now.format(&time::format_description::well_known::Rfc3339).unwrap_or_else(|_| String::from("[TIME_ERROR]"));
        println!("[{}] {}", timestamp, format!($($arg)*));
    }};
}

const BROADCAST_PORT: u16 = 39002;
const BROADCAST_MESSAGE: &str = "PLAN1_PEER_DISCOVERY";

pub async fn send_broadcast() -> Result<(), Box<dyn std::error::Error>> {
    log!("Broadcasting peer discovery message on all interfaces");

    // Create UDP socket
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.set_broadcast(true)?;

    // Get our hostname
    let hostname = gethostname::gethostname()
        .to_string_lossy()
        .to_string();

    // Create broadcast message with hostname
    let message = format!("{}:{}", BROADCAST_MESSAGE, hostname);

    // Send to IPv4 broadcast address
    let broadcast_addr = SocketAddr::from((Ipv4Addr::BROADCAST, BROADCAST_PORT));
    let sent = socket.send_to(message.as_bytes(), broadcast_addr).await?;
    log!("✓ Sent {} bytes to broadcast address {}", sent, broadcast_addr);

    Ok(())
}

pub async fn start_broadcast_listener(
    verified_peers: Arc<RwLock<std::collections::HashSet<String>>>,
    connections: Arc<RwLock<HashMap<String, ConnectionInfo>>>,
) -> Result<(), Box<dyn std::error::Error>> {
    log!("Starting broadcast listener on port {}", BROADCAST_PORT);

    // Bind to broadcast port
    let socket = UdpSocket::bind(format!("0.0.0.0:{}", BROADCAST_PORT)).await?;
    socket.set_broadcast(true)?;

    let mut buf = [0u8; 1024];

    loop {
        match socket.recv_from(&mut buf).await {
            Ok((len, addr)) => {
                let message = String::from_utf8_lossy(&buf[..len]);
                log!("Received broadcast from {}: {}", addr, message);

                if message.starts_with(BROADCAST_MESSAGE) {
                    // Extract hostname from message
                    let hostname = if let Some(colon_pos) = message.find(':') {
                        message[colon_pos + 1..].to_string()
                    } else {
                        format!("peer-{}", addr.ip())
                    };

                    let peer_ip = addr.ip().to_string();
                    let peer_port = 39001; // Default HTTPS port
                    let peer_key = format!("{}:{}", peer_ip, peer_port);

                    // Check if we already know this peer
                    {
                        let peers = verified_peers.read().await;
                        if peers.contains(&peer_key) {
                            log!("Already know peer {}, skipping", peer_key);
                            continue;
                        }
                    }

                    log!("Discovered new peer via broadcast: {} ({})", peer_key, hostname);

                    // Add to verified peers before connecting
                    {
                        let mut peers = verified_peers.write().await;
                        peers.insert(peer_key.clone());
                    }

                    // Attempt to connect to the discovered peer
                    let verified_peers_clone = verified_peers.clone();
                    let connections_clone = connections.clone();
                    let peer_key_clone = peer_key.clone();
                    let peer_ip_clone = peer_ip.clone();
                    let hostname_clone = hostname.clone();

                    tokio::spawn(async move {
                        let connection_succeeded = match crate::peer_client::connect_to_peer(&peer_ip_clone, peer_port, true).await {
                            Ok(_) => {
                                log!("✓ Successfully connected to broadcast-discovered peer: {}", peer_key_clone);
                                true
                            }
                            Err(e) => {
                                log!("⚠ Failed to connect to broadcast-discovered peer {}: {}", peer_key_clone, e);
                                false
                            }
                        };

                        if connection_succeeded {
                            // Add to connections tracking
                            let now_utc = time::OffsetDateTime::now_utc();
                            let timestamp = now_utc.format(&time::format_description::well_known::Rfc3339)
                                .unwrap_or_else(|_| String::from("unknown"));

                            let mut conns = connections_clone.write().await;
                            conns.entry(peer_key_clone.clone())
                                .or_insert_with(|| {
                                    ConnectionInfo {
                                        hostname: hostname_clone,
                                        ip_address: peer_ip_clone,
                                        status: "Connected (Broadcast)".to_string(),
                                        connected_at: timestamp.clone(),
                                        last_message: "Broadcast discovery".to_string(),
                                        last_message_time: timestamp,
                                        request_count: 0,
                                        verified: true,
                                        last_heartbeat_sent: None,
                                        last_heartbeat_received: None,
                                        alive: true,
                                        current_version: None,
                                        version_history: vec![],
                                    }
                                });
                        } else {
                            // Remove from verified peers if connection failed
                            let mut peers = verified_peers_clone.write().await;
                            peers.remove(&peer_key_clone);
                        }
                    });
                }
            }
            Err(e) => {
                log!("Error receiving broadcast: {}", e);
            }
        }
    }
}
