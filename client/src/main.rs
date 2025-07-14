use shared::{Message, SystemMetrics, DEFAULT_HOST, DEFAULT_PORT};
use tokio_util::codec::{LengthDelimitedCodec, FramedRead, FramedWrite};
use bytes::Bytes;
use futures::{StreamExt, SinkExt};
use tracing::{info, error};
use tracing_subscriber::EnvFilter;
use tokio::net::TcpStream;
use clap::{Parser, Subcommand};
use uuid::Uuid;
use std::path::PathBuf;
use futures::Sink;

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
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let args = Args::parse();
    let addr = format!("{}:{}", args.host, args.port);
    
    match args.command {
        Commands::Ping => ping_agent(&addr).await?,
        Commands::Monitor => get_system_metrics(&addr).await?,
        Commands::SendFile { file, chunk_size } => send_file(&addr, &file, chunk_size).await?,
    }
    
         Ok(())
}

// Helper to send message via framed writer
async fn send_msg<W>(writer: &mut W, msg: &Message) -> std::io::Result<()> 
where
    W: Sink<Bytes, Error = std::io::Error> + Unpin,
{
    let bytes = Bytes::from(serde_json::to_vec(msg).expect("serialize"));
    writer.send(bytes).await
}

async fn ping_agent(addr: &str) -> Result<(), Box<dyn std::error::Error>> {
    info!("Connecting to agent at {}", addr);

    let stream = TcpStream::connect(addr).await?;
    let (read_half, write_half) = stream.into_split();
    let mut reader = FramedRead::new(read_half, LengthDelimitedCodec::new());
    let mut writer = FramedWrite::new(write_half, LengthDelimitedCodec::new());

    // Send ping
    info!("Sending ping...");
    send_msg(&mut writer, &Message::Ping).await?;

    // Read response
    if let Some(frame) = reader.next().await {
        let bytes = frame?;
        match serde_json::from_slice::<Message>(&bytes) {
            Ok(Message::Pong) => info!("Received pong! Agent is responding."),
            Ok(other) => info!("Unexpected response: {:?}", other),
            Err(e) => error!("Failed to parse response: {}", e),
        }
    }

    Ok(())
}

async fn get_system_metrics(addr: &str) -> Result<(), Box<dyn std::error::Error>> {
    info!("Connecting to agent at {}", addr);

    let stream = TcpStream::connect(addr).await?;
    let (read_half, write_half) = stream.into_split();
    let mut reader = FramedRead::new(read_half, LengthDelimitedCodec::new());
    let mut writer = FramedWrite::new(write_half, LengthDelimitedCodec::new());

    // Send system metrics request
    info!("Requesting system metrics...");
    send_msg(&mut writer, &Message::GetSystemMetrics).await?;

    // Read response
    if let Some(frame) = reader.next().await {
        let bytes = frame?;
        match serde_json::from_slice::<Message>(&bytes) {
            Ok(Message::SystemMetrics(metrics)) => display_system_metrics(&metrics),
            Ok(other) => info!("Unexpected response: {:?}", other),
            Err(e) => error!("Failed to parse response: {}", e),
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
    info!("Connecting to agent at {}", addr);

    // Check if file exists and get metadata
    let file_metadata = tokio::fs::metadata(file_path).await?;
    let file_size = file_metadata.len();
    let filename = file_path.file_name()
        .ok_or("Invalid filename")?
        .to_string_lossy()
        .to_string();

    info!("Preparing to send file: {} ({} bytes)", filename, file_size);

    // Connect to agent
    let stream = TcpStream::connect(addr).await?;
    let (read_half, write_half) = stream.into_split();
    let mut reader = FramedRead::new(read_half, LengthDelimitedCodec::new());
    let mut writer = FramedWrite::new(write_half, LengthDelimitedCodec::new());

    // Generate transfer ID
    let transfer_id = Uuid::new_v4();

    // Send StartFileTransfer message
    info!("Starting file transfer...");
    let start_message = Message::StartFileTransfer {
        transfer_id,
        filename: filename.clone(),
        total_size: file_size,
        chunk_size,
    };
    send_msg(&mut writer, &start_message).await?;

    // Wait for FileTransferReady response
    let mut frame = reader.next().await.ok_or("No response from agent")??;
    match serde_json::from_slice::<Message>(&frame)? {
        Message::FileTransferReady { transfer_id: ready_id } if ready_id == transfer_id => {
            info!("Agent ready to receive file");
        }
        other => return Err(format!("Unexpected response: {:?}", other).into()),
    }

    // Open the file and read in chunks
    use tokio::io::AsyncReadExt;
    let mut file = tokio::fs::File::open(file_path).await?;
    let mut buffer = vec![0u8; chunk_size as usize];
    let mut chunk_number = 0u32;
    let mut bytes_sent: u64 = 0;

    loop {
        let n = file.read(&mut buffer).await?;
        if n == 0 { break; }
        bytes_sent += n as u64;

        let is_last_chunk = bytes_sent == file_size;
        let chunk_data = buffer[..n].to_vec();

        let chunk_message = Message::FileChunk {
            transfer_id,
            chunk_number,
            data: chunk_data,
            is_last_chunk,
        };
        send_msg(&mut writer, &chunk_message).await?;

        // Wait for ChunkReceived acknowledgment
        let frame = reader.next().await.ok_or("No ack from agent")??;
        match serde_json::from_slice::<Message>(&frame)? {
            Message::ChunkReceived { transfer_id: ack_id, chunk_number: ack_chunk } if ack_id == transfer_id && ack_chunk == chunk_number => {
                info!("Chunk {} acknowledged", chunk_number);
            }
            other => return Err(format!("Unexpected response: {:?}", other).into()),
        }

        chunk_number += 1;
    }

    // Send CompleteFileTransfer message
    send_msg(&mut writer, &Message::CompleteFileTransfer { transfer_id }).await?;

    // Wait for FileTransferComplete response
    let frame = reader.next().await.ok_or("No completion response")??;
    match serde_json::from_slice::<Message>(&frame)? {
        Message::FileTransferComplete { success, error, .. } => {
            if success {
                info!("File transfer completed successfully!");
            } else {
                info!("File transfer failed: {:?}", error);
            }
        }
        other => info!("Unexpected response: {:?}", other),
    }

    Ok(())
}
