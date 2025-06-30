use shared::{Message, SystemMetrics, DEFAULT_HOST, DEFAULT_PORT};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use clap::{Parser, Subcommand};
use uuid::Uuid;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "ferrolink-client")]
#[command(about = "FerroLink Client - Remote desktop monitoring and control")]
struct Args {
    #[arg(short = 'H', long, default_value = DEFAULT_HOST)]
    host: String,
    
    #[arg(short, long, default_value_t = DEFAULT_PORT)]
    port: u16,
    
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Test connection to the agent
    Ping,
    /// Get current system metrics
    Monitor,
    /// Send a file to the agent
    SendFile {
        /// Path to the file to send
        file: PathBuf,
        /// Chunk size in bytes (default: 8192)
        #[arg(long, default_value_t = 8192)]
        chunk_size: u32,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let addr = format!("{}:{}", args.host, args.port);
    
    match args.command {
        Commands::Ping => ping_agent(&addr).await?,
        Commands::Monitor => get_system_metrics(&addr).await?,
        Commands::SendFile { file, chunk_size } => send_file(&addr, &file, chunk_size).await?,
    }
    
         Ok(())
}

async fn ping_agent(addr: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("Connecting to agent at {}", addr);
    
    let mut stream = TcpStream::connect(addr).await?;
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
            println!("Received pong! Agent is responding.");
        }
        Ok(other) => {
            println!("Unexpected response: {:?}", other);
        }
        Err(e) => {
            eprintln!("Failed to parse response: {}", e);
        }
    }
    
    Ok(())
}

async fn get_system_metrics(addr: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("Connecting to agent at {}", addr);
    
    let mut stream = TcpStream::connect(addr).await?;
    let (reader, mut writer) = stream.split();
    let mut reader = BufReader::new(reader);
    
    // Send system metrics request
    println!("Requesting system metrics...");
    let request_json = serde_json::to_string(&Message::GetSystemMetrics)?;
    writer.write_all(request_json.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;
    
    // Read response
    let mut line = String::new();
    reader.read_line(&mut line).await?;
    
    match serde_json::from_str::<Message>(&line.trim()) {
        Ok(Message::SystemMetrics(metrics)) => {
            display_system_metrics(&metrics);
        }
        Ok(other) => {
            println!("Unexpected response: {:?}", other);
        }
        Err(e) => {
            eprintln!("Failed to parse response: {}", e);
        }
    }
    
    Ok(())
}

fn display_system_metrics(metrics: &SystemMetrics) {
    println!("\nSystem Metrics");
    println!("{}", "─".repeat(50));
    
    // Display CPU usage
    println!("CPU Usage: {:.1}%", metrics.cpu_usage_percent);
    
    // Display memory usage
    let memory = &metrics.memory;
    let memory_used_gb = memory.used_bytes as f64 / 1024.0 / 1024.0 / 1024.0;
    let memory_total_gb = memory.total_bytes as f64 / 1024.0 / 1024.0 / 1024.0;
    
    println!("Memory: {:.1} GB / {:.1} GB ({:.1}%)", 
        memory_used_gb, 
        memory_total_gb, 
        memory.usage_percent
    );
    
    // Display disk usage
    if !metrics.disks.is_empty() {
        println!("\nDisk Usage:");
        for disk in &metrics.disks {
            let used_gb = disk.used_bytes as f64 / 1024.0 / 1024.0 / 1024.0;
            let total_gb = disk.total_bytes as f64 / 1024.0 / 1024.0 / 1024.0;
            
            println!("   {} ({}): {:.1} GB / {:.1} GB ({:.1}%)",
                disk.name,
                disk.mount_point,
                used_gb,
                total_gb,
                disk.usage_percent
            );
        }
    }
    
    println!();
}

async fn send_file(addr: &str, file_path: &PathBuf, chunk_size: u32) -> Result<(), Box<dyn std::error::Error>> {
    println!("Connecting to agent at {}", addr);
    
    // Check if file exists and get metadata
    let file_metadata = tokio::fs::metadata(file_path).await?;
    let file_size = file_metadata.len();
    let filename = file_path.file_name()
        .ok_or("Invalid filename")?
        .to_string_lossy()
        .to_string();
    
    println!("Preparing to send file: {} ({} bytes)", filename, file_size);
    
    // Connect to agent
    let mut stream = TcpStream::connect(addr).await?;
    let (reader, mut writer) = stream.split();
    let mut reader = BufReader::new(reader);
    
    // Generate transfer ID
    let transfer_id = Uuid::new_v4();
    
    // Send StartFileTransfer message
    println!("Starting file transfer...");
    let start_message = Message::StartFileTransfer {
        transfer_id,
        filename: filename.clone(),
        total_size: file_size,
        chunk_size,
    };
    
    let start_json = serde_json::to_string(&start_message)?;
    writer.write_all(start_json.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;
    
    // Wait for FileTransferReady response
    let mut line = String::new();
    reader.read_line(&mut line).await?;
    
    match serde_json::from_str::<Message>(&line.trim())? {
        Message::FileTransferReady { transfer_id: ready_id } => {
            if ready_id != transfer_id {
                return Err("Transfer ID mismatch".into());
            }
            println!("Agent ready to receive file");
        }
        other => {
            return Err(format!("Unexpected response: {:?}", other).into());
        }
    }
    
    // Read file and send chunks
    let file_data = tokio::fs::read(file_path).await?;
    let total_chunks = ((file_size + chunk_size as u64 - 1) / chunk_size as u64) as u32;
    
    println!("Sending {} chunks...", total_chunks);
    
    for chunk_number in 0..total_chunks {
        let start_byte = (chunk_number as u64 * chunk_size as u64) as usize;
        let end_byte = std::cmp::min(start_byte + chunk_size as usize, file_data.len());
        let chunk_data = file_data[start_byte..end_byte].to_vec();
        let is_last_chunk = chunk_number == total_chunks - 1;
        
        // Send chunk
        let chunk_message = Message::FileChunk {
            transfer_id,
            chunk_number,
            data: chunk_data,
            is_last_chunk,
        };
        
        let chunk_json = serde_json::to_string(&chunk_message)?;
        writer.write_all(chunk_json.as_bytes()).await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;
        
        // Wait for acknowledgment
        line.clear();
        reader.read_line(&mut line).await?;
        
        match serde_json::from_str::<Message>(&line.trim())? {
            Message::ChunkReceived { transfer_id: ack_id, chunk_number: ack_chunk } => {
                if ack_id != transfer_id || ack_chunk != chunk_number {
                    return Err("Chunk acknowledgment mismatch".into());
                }
                print!("\rProgress: {}/{} chunks sent", chunk_number + 1, total_chunks);
                std::io::Write::flush(&mut std::io::stdout())?;
            }
            other => {
                return Err(format!("Unexpected chunk response: {:?}", other).into());
            }
        }
    }
    
    println!(); // New line after progress
    
    // Wait for completion response (the agent should send this automatically)
    line.clear();
    reader.read_line(&mut line).await?;
    
    match serde_json::from_str::<Message>(&line.trim())? {
        Message::FileTransferComplete { transfer_id: complete_id, success, error } => {
            if complete_id != transfer_id {
                return Err("Transfer completion ID mismatch".into());
            }
            
            if success {
                println!("File transfer completed successfully!");
                println!("File saved as: {}", filename);
            } else {
                println!("File transfer failed!");
                if let Some(err) = error {
                    println!("Error: {}", err);
                }
            }
        }
        other => {
            return Err(format!("Unexpected completion response: {:?}", other).into());
        }
    }
    
    Ok(())
}
