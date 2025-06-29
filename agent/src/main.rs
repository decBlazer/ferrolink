use shared::{Message, SystemMetrics, MemoryInfo, DiskInfo, DEFAULT_HOST, DEFAULT_PORT};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use sysinfo::{System, SystemExt, DiskExt, CpuExt};
use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
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

async fn handle_client(mut stream: TcpStream) -> Result<()> {
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
