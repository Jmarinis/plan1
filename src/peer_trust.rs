use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufReader, Write};
use std::path::Path;

const TRUSTED_PEERS_FILE: &str = "certs/trusted_peers.json";

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PeerInfo {
    pub fingerprint: String,
    #[serde(default = "default_hostname")]
    pub hostname: String,
    pub first_seen: String,
    pub last_seen: String,
}

fn default_hostname() -> String {
    "unknown".to_string()
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TrustedPeers {
    peers: HashMap<String, PeerInfo>,
}

impl TrustedPeers {
    pub fn load() -> Result<Self, Box<dyn std::error::Error>> {
        if Path::new(TRUSTED_PEERS_FILE).exists() {
            let file = File::open(TRUSTED_PEERS_FILE)?;
            let metadata = file.metadata()?;
            
            // If file is empty or too small, return empty peers
            if metadata.len() == 0 {
                return Ok(TrustedPeers {
                    peers: HashMap::new(),
                });
            }
            
            let reader = BufReader::new(file);
            match serde_json::from_reader(reader) {
                Ok(peers) => Ok(peers),
                Err(_) => {
                    // If parsing fails, return empty peers (file might be corrupted)
                    Ok(TrustedPeers {
                        peers: HashMap::new(),
                    })
                }
            }
        } else {
            Ok(TrustedPeers {
                peers: HashMap::new(),
            })
        }
    }

    pub fn save(&self) -> Result<(), Box<dyn std::error::Error>> {
        fs::create_dir_all("certs")?;
        let json = serde_json::to_string_pretty(&self)?;
        let mut file = File::create(TRUSTED_PEERS_FILE)?;
        file.write_all(json.as_bytes())?;
        Ok(())
    }

    pub fn is_trusted(&self, peer_address: &str, fingerprint: &str) -> bool {
        if let Some(peer_info) = self.peers.get(peer_address) {
            peer_info.fingerprint == fingerprint
        } else {
            false
        }
    }

    pub fn add_peer(&mut self, peer_address: String, fingerprint: String, hostname: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
        let now = time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| String::from("unknown"));
        
        if let Some(peer_info) = self.peers.get_mut(&peer_address) {
            // Update existing peer
            if peer_info.fingerprint != fingerprint {
                return Err(format!(
                    "Certificate mismatch for peer {}! Expected: {}, Got: {}",
                    peer_address, peer_info.fingerprint, fingerprint
                ).into());
            }
            peer_info.last_seen = now.clone();
            // Update hostname if provided
            if let Some(h) = hostname.clone() {
                peer_info.hostname = h;
            }
        } else {
            // Add new peer
            let new_hostname = hostname.clone().unwrap_or_else(|| format!("peer-{}", peer_address));
            self.peers.insert(
                peer_address.clone(),
                PeerInfo {
                    fingerprint,
                    hostname: new_hostname,
                    first_seen: now.clone(),
                    last_seen: now,
                },
            );
        }
        
        self.save()?;
        Ok(())
    }

    pub fn get_peer_info(&self, peer_address: &str) -> Option<&PeerInfo> {
        self.peers.get(peer_address)
    }

    pub fn list_peers(&self) -> Vec<(String, PeerInfo)> {
        self.peers
            .iter()
            .map(|(addr, info)| (addr.clone(), info.clone()))
            .collect()
    }

    pub fn remove_peer(&mut self, peer_address: &str) -> Result<(), Box<dyn std::error::Error>> {
        self.peers.remove(peer_address);
        self.save()?;
        Ok(())
    }
}

// Certificate verification for TOFU
pub fn verify_peer_certificate(
    peer_address: &str,
    cert_der: &[u8],
    auto_trust: bool,
    hostname: Option<String>,
) -> Result<bool, Box<dyn std::error::Error>> {
    use sha2::{Digest, Sha256};
    
    // Calculate fingerprint of the presented certificate
    let mut hasher = Sha256::new();
    hasher.update(cert_der);
    let fingerprint = hex::encode(hasher.finalize());
    
    let mut trusted_peers = TrustedPeers::load()?;
    
    if let Some(peer_info) = trusted_peers.get_peer_info(peer_address) {
        // Known peer - verify fingerprint matches
        if peer_info.fingerprint == fingerprint {
            println!("✓ Verified known peer: {} ({})", peer_address, peer_info.hostname);
            trusted_peers.add_peer(peer_address.to_string(), fingerprint, hostname)?;
            Ok(true)
        } else {
            println!("⚠ WARNING: Certificate changed for peer {}!", peer_address);
            println!("  Expected: {}", peer_info.fingerprint);
            println!("  Received: {}", fingerprint);
            println!("  This could indicate a security issue!");
            Ok(false)
        }
    } else {
        // New peer - TOFU
        let display_name = hostname.as_deref().unwrap_or(peer_address);
        println!("⚠ New peer connecting: {} ({})", peer_address, display_name);
        println!("  Fingerprint: {}", fingerprint);
        
        if auto_trust {
            println!("  Auto-trusting (TOFU enabled)");
            trusted_peers.add_peer(peer_address.to_string(), fingerprint, hostname)?;
            Ok(true)
        } else {
            println!("  Trust this peer? (y/n)");
            // In a real implementation, you'd want user input here
            // For now, we'll auto-trust in server mode
            trusted_peers.add_peer(peer_address.to_string(), fingerprint, hostname)?;
            Ok(true)
        }
    }
}
