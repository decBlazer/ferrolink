use shared::{Message, DEFAULT_HOST, DEFAULT_PORT};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = format!("{}:{}", DEFAULT_HOST, DEFAULT_PORT);
    println!("Starting agent on {}", addr);
    
    let listener = TcpListener::bind(&addr).await?;
    println!("Agent listening on {}", addr);
    
    loop {
        let (stream, peer_addr) = listener.accept().await?;
        println!("New client connected: {}", peer_addr);
        
        tokio::spawn(async move {
            if let Err(e) = handle_client(stream).await {
                eprintln!("Error handling client {}: {}", peer_addr, e);
            }
            println!("Client {} disconnected", peer_addr);
        });
    }
}

async fn handle_client(mut stream: TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    let (reader, mut writer) = stream.split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    
    loop {
        line.clear();
        match reader.read_line(&mut line).await? {
            0 => break, // Client disconnected
            _ => {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                
                match serde_json::from_str::<Message>(line) {
                    Ok(Message::Ping) => {
                        println!("Received ping");
                        let response = serde_json::to_string(&Message::Pong)?;
                        writer.write_all(response.as_bytes()).await?;
                        writer.write_all(b"\n").await?;
                        writer.flush().await?;
                    }
                    Ok(other) => {
                        println!("Received unexpected message: {:?}", other);
                    }
                    Err(e) => {
                        eprintln!("Failed to parse message: {}", e);
                    }
                }
            }
        }
    }
    
    Ok(())
}
