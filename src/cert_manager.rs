use rcgen::{CertificateParams, KeyPair};
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use sha2::{Sha256, Digest};

const CERT_DIR: &str = "certs";
const CERT_FILE: &str = "certs/server_cert.pem";
const KEY_FILE: &str = "certs/server_key.pem";

pub fn ensure_certificate() -> Result<(), Box<dyn std::error::Error>> {
    // Create certs directory if it doesn't exist
    fs::create_dir_all(CERT_DIR)?;

    // Check if certificate already exists
    if Path::new(CERT_FILE).exists() && Path::new(KEY_FILE).exists() {
        println!("Using existing certificate");
        return Ok(());
    }

    println!("Generating new self-signed certificate...");
    
    // Generate a new key pair
    let key_pair = KeyPair::generate(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    
    // Create certificate parameters
    let mut params = CertificateParams::default();
    params.distinguished_name.push(
        rcgen::DnType::CommonName,
        "P2P Node"
    );
    
    // Add subject alternative names for common use cases
    params.subject_alt_names = vec![
        rcgen::SanType::DnsName("localhost".to_string()),
        rcgen::SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))),
    ];
    
    // Set validity period (1 year)
    params.not_before = time::OffsetDateTime::now_utc();
    params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(365);
    
    // Generate the certificate
    let cert = rcgen::Certificate::from_params(params)?;
    
    // Serialize to PEM
    let cert_pem = cert.serialize_pem()?;
    let key_pem = key_pair.serialize_pem();
    
    // Write to files
    let mut cert_file = File::create(CERT_FILE)?;
    cert_file.write_all(cert_pem.as_bytes())?;
    
    let mut key_file = File::create(KEY_FILE)?;
    key_file.write_all(key_pem.as_bytes())?;
    
    // Calculate and display fingerprint
    let fingerprint = calculate_fingerprint(&cert_pem)?;
    println!("Certificate generated successfully!");
    println!("Fingerprint (SHA-256): {}", fingerprint);
    
    Ok(())
}

pub fn calculate_fingerprint(cert_pem: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut hasher = Sha256::new();
    hasher.update(cert_pem.as_bytes());
    let result = hasher.finalize();
    Ok(hex::encode(result))
}

pub fn get_cert_fingerprint() -> Result<String, Box<dyn std::error::Error>> {
    let cert_pem = fs::read_to_string(CERT_FILE)?;
    calculate_fingerprint(&cert_pem)
}

pub fn get_cert_path() -> &'static str {
    CERT_FILE
}

pub fn get_key_path() -> &'static str {
    KEY_FILE
}
