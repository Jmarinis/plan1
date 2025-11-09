use rustls::client::{ServerCertVerified, ServerCertVerifier};
use rustls::{Certificate, Error as TlsError, ServerName};
use std::sync::Arc;
use std::time::SystemTime;
use crate::peer_trust;

/// Custom certificate verifier that implements Trust-On-First-Use (TOFU)
pub struct TofuServerCertVerifier {
    peer_address: String,
}

impl TofuServerCertVerifier {
    pub fn new(peer_address: String) -> Arc<Self> {
        Arc::new(Self { peer_address })
    }
}

impl ServerCertVerifier for TofuServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &Certificate,
        _intermediates: &[Certificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: SystemTime,
    ) -> Result<ServerCertVerified, TlsError> {
        // Calculate fingerprint of the presented certificate
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&end_entity.0);
        let fingerprint = hex::encode(hasher.finalize());
        
        // Load trusted peers
        let mut trusted_peers = peer_trust::TrustedPeers::load()
            .map_err(|e| TlsError::General(format!("Failed to load trusted peers: {}", e)))?;
        
        if let Some(peer_info) = trusted_peers.get_peer_info(&self.peer_address) {
            // Known peer - verify fingerprint matches
            if peer_info.fingerprint == fingerprint {
                println!("✓ Verified known peer: {}", self.peer_address);
                // Update last seen
                let _ = trusted_peers.add_peer(self.peer_address.clone(), fingerprint);
                Ok(ServerCertVerified::assertion())
            } else {
                println!("⚠ WARNING: Certificate changed for peer {}!", self.peer_address);
                println!("  Expected: {}", peer_info.fingerprint);
                println!("  Received: {}", fingerprint);
                Err(TlsError::General("Certificate fingerprint mismatch".to_string()))
            }
        } else {
            // New peer - TOFU: trust on first use
            println!("⚠ New peer: {} (fingerprint: {}...)", self.peer_address, &fingerprint[..16]);
            println!("  Auto-trusting (TOFU)");
            
            match trusted_peers.add_peer(self.peer_address.clone(), fingerprint) {
                Ok(_) => Ok(ServerCertVerified::assertion()),
                Err(e) => Err(TlsError::General(format!("Failed to trust peer: {}", e))),
            }
        }
    }
}

/// Verifier that accepts any certificate (for initial handshake on server side)
pub struct AcceptAnyCertVerifier;

impl AcceptAnyCertVerifier {
    pub fn new() -> Arc<Self> {
        Arc::new(Self)
    }
}

impl rustls::server::ClientCertVerifier for AcceptAnyCertVerifier {
    fn client_auth_root_subjects(&self) -> Option<rustls::DistinguishedNames> {
        Some(rustls::DistinguishedNames::new())
    }

    fn verify_client_cert(
        &self,
        _end_entity: &Certificate,
        _intermediates: &[Certificate],
        _now: SystemTime,
    ) -> Result<rustls::server::ClientCertVerified, TlsError> {
        // Accept any certificate - we'll verify via reverse connection
        Ok(rustls::server::ClientCertVerified::assertion())
    }
}
