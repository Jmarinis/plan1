use rustls::client::{ServerCertVerified, ServerCertVerifier};
use rustls::{Certificate, Error as TlsError, ServerName};
use std::sync::Arc;
use std::time::SystemTime;
use crate::peer_trust;

/// Custom certificate verifier that implements Trust-On-First-Use (TOFU)
/// This verifier accepts self-signed certificates and validates them using fingerprint matching
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
                println!("[CERT] ✓ Verified known peer: {}", self.peer_address);
                println!("[CERT]   Fingerprint matches: {}...", &fingerprint[..16]);
                // Update last seen (hostname not available in cert verifier)
                let _ = trusted_peers.add_peer(self.peer_address.clone(), fingerprint, None);
                Ok(ServerCertVerified::assertion())
            } else {
                println!("[CERT] ✗ WARNING: Certificate changed for peer {}!", self.peer_address);
                println!("[CERT]   Expected: {}...", &peer_info.fingerprint[..16]);
                println!("[CERT]   Received: {}...", &fingerprint[..16]);
                println!("[CERT]   This could indicate a security issue!");
                Err(TlsError::General("Certificate fingerprint mismatch".to_string()))
            }
        } else {
            // New peer - TOFU: trust on first use
            println!("[CERT] New peer detected: {}", self.peer_address);
            println!("[CERT]   Fingerprint: {}...", &fingerprint[..16]);
            println!("[CERT]   Auto-trusting (TOFU)");
            
            match trusted_peers.add_peer(self.peer_address.clone(), fingerprint.clone(), None) {
                Ok(_) => {
                    println!("[CERT] ✓ Peer {} added to trusted list", self.peer_address);
                    Ok(ServerCertVerified::assertion())
                },
                Err(e) => {
                    println!("[CERT] ✗ Failed to trust peer: {}", e);
                    Err(TlsError::General(format!("Failed to trust peer: {}", e)))
                },
            }
        }
    }
    
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &Certificate,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::HandshakeSignatureValid, TlsError> {
        // Accept any signature for self-signed certificates
        Ok(rustls::client::HandshakeSignatureValid::assertion())
    }
    
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &Certificate,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::HandshakeSignatureValid, TlsError> {
        // Accept any signature for self-signed certificates
        Ok(rustls::client::HandshakeSignatureValid::assertion())
    }
    
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        // Support all schemes since we're not actually verifying signatures
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

// Dummy implementation to satisfy the old interface
#[allow(dead_code)]
impl TofuServerCertVerifier {
    // Old verify_server_cert method - now handled by the trait implementation above
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
