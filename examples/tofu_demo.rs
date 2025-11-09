// Example demonstrating Trust-On-First-Use (TOFU) functionality
// 
// This example shows how to:
// 1. Start a server with auto-generated certificates
// 2. Connect to peers and trust their certificates
// 3. Verify subsequent connections

use plan1::peer_client;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== P2P TOFU Demo ===\n");
    
    // List currently trusted peers
    println!("1. Checking trusted peers:");
    peer_client::list_trusted_peers()?;
    println!();
    
    // Example: Connect to a peer (uncomment to use)
    // println!("2. Connecting to peer...");
    // match peer_client::connect_to_peer("192.168.1.100", 39001, true).await {
    //     Ok(_) => println!("✓ Connection successful!"),
    //     Err(e) => println!("✗ Connection failed: {}", e),
    // }
    // println!();
    
    // Example: List peers after connection
    // println!("3. Trusted peers after connection:");
    // peer_client::list_trusted_peers()?;
    // println!();
    
    // Example: Remove a peer from trusted list
    // println!("4. Removing peer from trusted list:");
    // peer_client::untrust_peer("192.168.1.100:39001")?;
    // println!();
    
    println!("Demo complete!");
    println!("\nTo use this in your application:");
    println!("  - Start your server with 'cargo run'");
    println!("  - Each server will generate its own certificate");
    println!("  - Connect peers using the peer_client module");
    println!("  - Certificates are automatically trusted on first connection");
    println!("  - Subsequent connections verify against stored fingerprints");
    
    Ok(())
}
