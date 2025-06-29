use shared::{Message, SystemMetrics, DEFAULT_HOST, DEFAULT_PORT};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use clap::{Parser, Subcommand};

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
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let addr = format!("{}:{}", args.host, args.port);
    
    match args.command {
        Commands::Ping => ping_agent(&addr).await?,
        Commands::Monitor => get_system_metrics(&addr).await?,
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
