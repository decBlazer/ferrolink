use shared::{Message, DEFAULT_HOST, DEFAULT_PORT};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = format!("{}:{}", DEFAULT_HOST, DEFAULT_PORT);
    println!("Connecting to agent at {}", addr);
    
    let mut stream = TcpStream::connect(&addr).await?;
    let (reader, mut writer) = stream.split();
    let mut reader = BufReader::new(reader);
    
    // Send ping
    println!("Sending ping...");
    let ping_json = serde_json::to_string(&Message::Ping)?;
    writer.write_all(ping_json.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;
    
    // Read response
    let mut line = String::new();
    reader.read_line(&mut line).await?;
    
    match serde_json::from_str::<Message>(&line.trim()) {
        Ok(Message::Pong) => {
            println!("✅ Received pong! Agent is responding.");
        }
        Ok(other) => {
            println!("❓ Unexpected response: {:?}", other);
        }
        Err(e) => {
            eprintln!("❌ Failed to parse response: {}", e);
        }
    }
    
         Ok(())
}
