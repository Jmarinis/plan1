// Library entry point for plan1 P2P TOFU implementation

pub mod cert_manager;
pub mod peer_trust;
pub mod peer_client;
pub mod cert_verifier;
pub mod broadcast;

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct VersionInfo {
    pub version: String,
    pub first_seen: String,
    pub last_seen: String,
    pub seen_count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConnectionInfo {
    pub hostname: String,
    pub ip_address: String,
    pub status: String,
    pub connected_at: String,
    pub last_message: String,
    pub last_message_time: String,
    pub request_count: usize,
    pub verified: bool,
    pub last_heartbeat_sent: Option<String>,
    pub last_heartbeat_received: Option<String>,
    pub alive: bool,
    pub current_version: Option<String>,
    pub version_history: Vec<VersionInfo>,
}
