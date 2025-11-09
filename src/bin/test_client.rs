// Test client to demonstrate bidirectional certificate exchange
// Run this alongside the main server to test P2P certificate trust

use plan1::{cert_manager, peer_client};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== P2P Certificate Exchange Test Client ===\n");
    
    // Ensure we have a certificate
    cert_manager::ensure_certificate()?;
    let fingerprint = cert_manager::get_cert_fingerprint()?;
    println!("Our fingerprint: {}\n", fingerprint);
    
    // Get peer address from command line or use default
    let args: Vec<String> = std::env::args().collect();
    let peer_address = if args.len() > 1 {
        args[1].clone()
    } else {
        println!("Usage: test_client <peer_ip>");
        println!("Example: test_client 192.168.1.100");
        println!("\nUsing default: 127.0.0.1");
        "127.0.0.1".to_string()
    };
    
    println!("Connecting to peer: {}:39001", peer_address);
    println!("This will:");
    println!("  1. Connect to the peer");
    println!("  2. Perform TLS handshake");
    println!("  3. Trust peer's certificate (TOFU)");
    println!("  4. Peer will connect back to verify our certificate");
    println!("  5. Mutual trust established\n");
    
    // Connect to peer
    match peer_client::connect_to_peer(&peer_address, 39001, true).await {
        Ok(_) => {
            println!("\n✓ Successfully connected and exchanged certificates!");
            println!("\nYou can verify by checking:");
            println!("  - This client's certs/trusted_peers.json");
            println!("  - The server's certs/trusted_peers.json");
            println!("  - Both should contain each other's fingerprints");
        }
        Err(e) => {
            println!("\n✗ Connection failed: {}", e);
            println!("\nPossible reasons:");
            println!("  - Peer is not running on {}:39001", peer_address);
            println!("  - Firewall blocking connection");
            println!("  - Peer is not accepting connections");
        }
    }
    
    // List trusted peers
    println!("\n--- Trusted Peers ---");
    peer_client::list_trusted_peers()?;
    
    Ok(())
}
