use std::{fs, sync::Arc};
use tokio::net::TcpListener;
use rustls::{ServerConfig, Certificate, PrivateKey};
use tokio_rustls::TlsAcceptor;
use tokio::io::{AsyncReadExt, AsyncWriteExt}; // Import the async traits

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load TLS certificate and private key
    let certs = load_certs("cert.pem")?;
    let key = load_private_key("key.pem")?;

    // Configure rustls server without client authentication
    let config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| e.to_string())?;
    
    let acceptor = TlsAcceptor::from(Arc::new(config));

    // Bind the TCP listener to port 443 (HTTPS)
    let listener = TcpListener::bind("0.0.0.0:39001").await?;
    println!("HTTPS server listening on port 39001");

    loop {
        // Accept new TCP connections
        let (stream, addr) = listener.accept().await?;
        println!("New connection from {:?}", addr);

        // Upgrade the TCP connection to TLS
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let tls_stream = acceptor.accept(stream).await;
            match tls_stream {
                Ok(mut stream) => {
                    println!("TLS connection established");

                    // Example: Read from the stream (you can write to it as well)
                    let mut buf = [0u8; 1024];
                    match stream.read(&mut buf).await {
                        Ok(n) if n > 0 => {
                            println!("Received: {:?}", &buf[..n]);

                            // Optionally, write back a response
                            let response = b"HTTP/1.1 200 OK\r\n\r\nHello, World!";
                            if let Err(e) = stream.write_all(response).await {
                                println!("Error writing to stream: {:?}", e);
                            }
                        }
                        Ok(_) => println!("Connection closed by client"),
                        Err(e) => println!("Error reading from stream: {:?}", e),
                    }
                }
                Err(e) => println!("TLS handshake failed: {:?}", e),
            }
        });
    }
}

fn load_certs(path: &str) -> Result<Vec<Certificate>, Box<dyn std::error::Error>> {
    let certfile = fs::File::open(path)?;
    let mut reader = std::io::BufReader::new(certfile);
    let certs = rustls_pemfile::certs(&mut reader)?
        .into_iter()
        .map(Certificate)
        .collect();
    Ok(certs)
}

fn load_private_key(path: &str) -> Result<PrivateKey, Box<dyn std::error::Error>> {
    let keyfile = fs::File::open(path)?;
    let mut reader = std::io::BufReader::new(keyfile);
    let keys = rustls_pemfile::pkcs8_private_keys(&mut reader)?
        .into_iter()
        .map(PrivateKey)
        .collect::<Vec<_>>();

    if keys.len() != 1 {
        return Err("Expected a single private key".into());
    }

    Ok(keys[0].clone())
}
