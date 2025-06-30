use shared::{Message, SystemMetrics, MemoryInfo, DiskInfo, DEFAULT_HOST, DEFAULT_PORT};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::net::tcp::WriteHalf;
use sysinfo::{System, SystemExt, DiskExt, CpuExt};
use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;
use clap::Parser;

#[derive(Parser)]
#[command(name = "ferrolink-agent")]
#[command(about = "FerroLink Agent - Remote desktop monitoring and control server")]
struct Args {
    #[arg(short = 'H', long, default_value = DEFAULT_HOST)]
    host: String,
    
    #[arg(short, long, default_value_t = DEFAULT_PORT)]
    port: u16,
    
    #[arg(short, long, default_value = "uploads")]
    upload_dir: String,
}

// File transfer state tracking
struct FileTransferState {
    filename: String,
    total_size: u64,
    #[allow(dead_code)]
    chunk_size: u32,
    expected_chunks: u32,
    received_chunks: HashMap<u32, Vec<u8>>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let addr = format!("{}:{}", args.host, args.port);
    println!("Starting agent on {}", addr);
    println!("Upload directory: {}", args.upload_dir);
    
    let listener = TcpListener::bind(&addr).await?;
    println!("Agent listening on {}", addr);
    
    // Shared state for file transfers across all client connections
    let file_transfers: Arc<Mutex<HashMap<Uuid, FileTransferState>>> = Arc::new(Mutex::new(HashMap::new()));
    let upload_dir = Arc::new(args.upload_dir);
    
    loop {
        let (stream, peer_addr) = listener.accept().await?;
        println!("New client connected: {}", peer_addr);
        
        let file_transfers_clone = Arc::clone(&file_transfers);
        let upload_dir_clone = Arc::clone(&upload_dir);
        tokio::spawn(async move {
            if let Err(e) = handle_client(stream, file_transfers_clone, upload_dir_clone).await {
                eprintln!("Error handling client {}: {}", peer_addr, e);
            }
            println!("Client {} disconnected", peer_addr);
        });
    }
}

async fn handle_client(
    mut stream: TcpStream, 
    file_transfers: Arc<Mutex<HashMap<Uuid, FileTransferState>>>,
    upload_dir: Arc<String>
) -> Result<()> {
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
                    Ok(Message::GetSystemMetrics) => {
                        println!("Received system metrics request");
                        match collect_system_metrics().await {
                            Ok(metrics) => {
                                let response = serde_json::to_string(&Message::SystemMetrics(metrics))?;
                                writer.write_all(response.as_bytes()).await?;
                                writer.write_all(b"\n").await?;
                                writer.flush().await?;
                            }
                            Err(e) => {
                                eprintln!("Failed to collect system metrics: {}", e);
                            }
                        }
                    }
                    Ok(file_transfer_msg @ (Message::StartFileTransfer { .. } | 
                                           Message::FileChunk { .. } | 
                                           Message::CompleteFileTransfer { .. })) => {
                        if let Err(e) = handle_file_transfer(file_transfer_msg, &mut writer, &file_transfers, &upload_dir).await {
                            eprintln!("Failed to handle file transfer: {}", e);
                        }
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

async fn collect_system_metrics() -> Result<SystemMetrics> {
    // Create system info collector
    let mut system = System::new_all();
    system.refresh_all();
    
    // Get CPU usage (average across all cores)
    let cpu_usage = system.cpus().iter()
        .map(|cpu| cpu.cpu_usage() as f64)
        .sum::<f64>() / system.cpus().len() as f64;
    
    // Get memory information
    let total_memory = system.total_memory();
    let used_memory = system.used_memory();
    let available_memory = total_memory - used_memory;
    let memory_usage_percent = (used_memory as f64 / total_memory as f64) * 100.0;
    
    let memory = MemoryInfo {
        total_bytes: total_memory,
        used_bytes: used_memory,
        available_bytes: available_memory,
        usage_percent: memory_usage_percent,
    };
    
    // Get disk information
    let mut disks = Vec::new();
    for disk in system.disks() {
        let total_space = disk.total_space();
        let available_space = disk.available_space();
        let used_space = total_space - available_space;
        let usage_percent = if total_space > 0 {
            (used_space as f64 / total_space as f64) * 100.0
        } else {
            0.0
        };
        
        disks.push(DiskInfo {
            name: disk.name().to_string_lossy().to_string(),
            mount_point: disk.mount_point().to_string_lossy().to_string(),
            total_bytes: total_space,
            used_bytes: used_space,
            available_bytes: available_space,
            usage_percent,
        });
    }
    
    Ok(SystemMetrics {
        cpu_usage_percent: cpu_usage,
        memory,
        disks,
    })
}

async fn handle_file_transfer(
    message: Message,
    writer: &mut WriteHalf<'_>,
    file_transfers: &Arc<Mutex<HashMap<Uuid, FileTransferState>>>,
    upload_dir: &str,
) -> Result<()> {
    match message {
        Message::StartFileTransfer { transfer_id, filename, total_size, chunk_size } => {
            println!("Starting file transfer: {} ({} bytes)", filename, total_size);
            
            // Calculate expected number of chunks
            let expected_chunks = ((total_size + chunk_size as u64 - 1) / chunk_size as u64) as u32;
            
            // Create new transfer state
            let transfer_state = FileTransferState {
                filename: filename.clone(),
                total_size,
                chunk_size,
                expected_chunks,
                received_chunks: HashMap::new(),
            };
            
            // Store the transfer state
            {
                let mut transfers = file_transfers.lock().await;
                transfers.insert(transfer_id, transfer_state);
            }
            
            // Send ready response
            let response = Message::FileTransferReady { transfer_id };
            let response_json = serde_json::to_string(&response)?;
            writer.write_all(response_json.as_bytes()).await?;
            writer.write_all(b"\n").await?;
            writer.flush().await?;
            
            println!("File transfer ready: {} (expecting {} chunks)", filename, expected_chunks);
        }
        
        Message::FileChunk { transfer_id, chunk_number, data, is_last_chunk: _ } => {
            println!("Received chunk {} for transfer {}", chunk_number, transfer_id);
            
            let mut should_complete = false;
            let filename;
            
            // Store the chunk
            {
                let mut transfers = file_transfers.lock().await;
                if let Some(transfer_state) = transfers.get_mut(&transfer_id) {
                    transfer_state.received_chunks.insert(chunk_number, data);
                    filename = transfer_state.filename.clone();
                    
                    // Check if we have all chunks
                    if transfer_state.received_chunks.len() as u32 == transfer_state.expected_chunks {
                        should_complete = true;
                    }
                } else {
                    eprintln!("Received chunk for unknown transfer: {}", transfer_id);
                    return Ok(());
                }
            }
            
            // Send chunk received acknowledgment
            let ack_response = Message::ChunkReceived { transfer_id, chunk_number };
            let ack_json = serde_json::to_string(&ack_response)?;
            writer.write_all(ack_json.as_bytes()).await?;
            writer.write_all(b"\n").await?;
            writer.flush().await?;
            
            // If this was the last chunk or we have all chunks, complete the transfer
            if should_complete {
                complete_file_transfer(transfer_id, &filename, writer, file_transfers, upload_dir).await?;
            }
        }
        
        Message::CompleteFileTransfer { transfer_id } => {
            println!("Completing file transfer: {}", transfer_id);
            
            let filename = {
                let transfers = file_transfers.lock().await;
                if let Some(transfer_state) = transfers.get(&transfer_id) {
                    transfer_state.filename.clone()
                } else {
                    eprintln!("Received complete request for unknown transfer: {}", transfer_id);
                    return Ok(());
                }
            };
            
            complete_file_transfer(transfer_id, &filename, writer, file_transfers, upload_dir).await?;
        }
        
        _ => {
            eprintln!("Unexpected message in file transfer handler: {:?}", message);
        }
    }
    
    Ok(())
}

async fn complete_file_transfer(
    transfer_id: Uuid,
    filename: &str,
    writer: &mut WriteHalf<'_>,
    file_transfers: &Arc<Mutex<HashMap<Uuid, FileTransferState>>>,
    upload_dir: &str,
) -> Result<()> {
    let transfer_result = {
        let mut transfers = file_transfers.lock().await;
        if let Some(transfer_state) = transfers.remove(&transfer_id) {
            // Reconstruct the file from chunks
            let mut file_data = Vec::with_capacity(transfer_state.total_size as usize);
            
            // Collect chunks in order
            for chunk_num in 0..transfer_state.expected_chunks {
                if let Some(chunk_data) = transfer_state.received_chunks.get(&chunk_num) {
                    file_data.extend_from_slice(chunk_data);
                } else {
                    return Ok(()); // Missing chunks, will send error response below
                }
            }
            
            // Create upload directory if it doesn't exist
            tokio::fs::create_dir_all(upload_dir).await.ok();
            
            // Write file to upload directory
            let file_path = format!("{}/{}", upload_dir, transfer_state.filename);
            match tokio::fs::write(&file_path, &file_data).await {
                Ok(_) => {
                    println!("Successfully wrote file: {} ({} bytes)", file_path, file_data.len());
                    Some((true, None))
                }
                Err(e) => {
                    eprintln!("Failed to write file {}: {}", transfer_state.filename, e);
                    Some((false, Some(format!("Failed to write file: {}", e))))
                }
            }
        } else {
            eprintln!("Transfer state not found for: {}", transfer_id);
            Some((false, Some("Transfer state not found".to_string())))
        }
    };
    
    // Send completion response
    if let Some((success, error)) = transfer_result {
        let response = Message::FileTransferComplete { transfer_id, success, error };
        let response_json = serde_json::to_string(&response)?;
        writer.write_all(response_json.as_bytes()).await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;
        
        if success {
            println!("File transfer completed successfully: {}", filename);
        } else {
            println!("File transfer failed: {}", filename);
        }
    }
    
    Ok(())
}
