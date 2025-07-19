use shared::{Message, SystemMetrics, MemoryInfo, DiskInfo, DEFAULT_HOST, DEFAULT_PORT};
use tokio_util::codec::{LengthDelimitedCodec, FramedRead, FramedWrite};
use bytes::Bytes;
use futures::{StreamExt, SinkExt};
use tokio::net::TcpListener;
use tokio::process::Command as TokioCommand;
use sysinfo::{System, SystemExt, DiskExt, CpuExt};
use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;
use clap::Parser;
use tracing::{info, error};
use tracing_subscriber::EnvFilter;
use futures::Sink;
use std::fs::File;
use std::io::BufReader;
use rustls::{Certificate, PrivateKey, ServerConfig};
use tokio_rustls::TlsAcceptor;
use rustls_pemfile::{certs, pkcs8_private_keys, rsa_private_keys};
// Add Prometheus / Hyper imports
use hyper::{Body, Request, Response, Server};
use hyper::service::{make_service_fn, service_fn};
use once_cell::sync::Lazy;
use prometheus::{Encoder, TextEncoder, IntCounter, register_int_counter};

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

    /// Path to TLS certificate PEM file
    #[arg(long, default_value = "cert.pem")]
    cert_path: String,

    /// Path to TLS private key PEM file
    #[arg(long, default_value = "key.pem")]
    key_path: String,

    /// Authentication token required from clients. If omitted, authentication is disabled.
    #[arg(long, env = "FERROLINK_TOKEN")]
    token: Option<String>,

    /// Port for Prometheus `/metrics` endpoint
    #[arg(long, default_value_t = 9090)]
    metrics_port: u16,
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

// Helper to send a Message via a framed writer
async fn send_msg<W>(writer: &mut W, msg: &Message) -> Result<()>
where
    W: Sink<Bytes, Error = std::io::Error> + Unpin,
{
    let bytes = Bytes::from(serde_json::to_vec(msg)?);
    writer.send(bytes).await.map_err(|e| e.into())
}

// Helper to load certificates
fn load_certs(path: &str) -> anyhow::Result<Vec<Certificate>> {
    let mut reader = BufReader::new(File::open(path)?);
    let certs = certs(&mut reader)?
        .into_iter()
        .map(Certificate)
        .collect();
    Ok(certs)
}

// Helper to load private key (PKCS8 or RSA)
fn load_private_key(path: &str) -> anyhow::Result<PrivateKey> {
    let mut reader = BufReader::new(File::open(path)?);
    // Try pkcs8 first
    if let Some(key) = pkcs8_private_keys(&mut reader)?.into_iter().next() {
        return Ok(PrivateKey(key));
    }
    // Rewind and try RSA
    let mut reader = BufReader::new(File::open(path)?);
    if let Some(key) = rsa_private_keys(&mut reader)?.into_iter().next() {
        return Ok(PrivateKey(key));
    }
    anyhow::bail!("No private key found in {}", path)
}

// ===================== Prometheus Metrics =====================
static CONNECTIONS_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!("connections_total", "Total TCP client connections").unwrap()
});
static AUTH_FAILURES_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!("auth_failures_total", "Failed client authentications").unwrap()
});
static FILE_TRANSFERS_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!("file_transfers_total", "Completed file transfers").unwrap()
});
// =============================================================

async fn start_metrics_server(addr: std::net::SocketAddr) -> Result<(), hyper::Error> {
    let make_svc = make_service_fn(|_conn| async {
        Ok::<_, hyper::Error>(service_fn(|req: Request<Body>| async move {
            if req.uri().path() == "/metrics" {
                let encoder = TextEncoder::new();
                let metric_families = prometheus::gather();
                let mut buffer = Vec::new();
                encoder.encode(&metric_families, &mut buffer).unwrap();
                Ok::<_, hyper::Error>(Response::builder()
                    .status(200)
                    .header("Content-Type", encoder.format_type())
                    .body(Body::from(buffer))
                    .unwrap())
            } else {
                Ok::<_, hyper::Error>(Response::builder()
                    .status(404)
                    .body(Body::from("Not Found"))
                    .unwrap())
            }
        }))
    });
    Server::bind(&addr).serve(make_svc).await
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing subscriber (env-controlled log level)
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let args = Args::parse();
    let addr = format!("{}:{}", args.host, args.port);
    info!("Starting agent on {}", addr);
    info!("Upload directory: {}", args.upload_dir);
    
    // Build TLS acceptor
    let certs = load_certs(&args.cert_path)?;
    let key = load_private_key(&args.key_path)?;
    let tls_config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    let acceptor = TlsAcceptor::from(Arc::new(tls_config));

    let listener = TcpListener::bind(&addr).await?;
    info!("Agent listening with TLS on {}", addr);
    
    // Shared state for file transfers across all client connections
    let file_transfers: Arc<Mutex<HashMap<Uuid, FileTransferState>>> = Arc::new(Mutex::new(HashMap::new()));
    let upload_dir = Arc::new(args.upload_dir);
    
    // Spawn Prometheus metrics endpoint
    let metrics_addr = format!("0.0.0.0:{}", args.metrics_port).parse().expect("metrics addr");
    tokio::spawn(async move {
        if let Err(e) = start_metrics_server(metrics_addr).await {
            eprintln!("Metrics server failed: {}", e);
        }
    });

    loop {
        let (tcp_stream, peer_addr) = listener.accept().await?;
        let acceptor = acceptor.clone();
        info!("New client connected: {}", peer_addr);
        CONNECTIONS_TOTAL.inc();
        
        let file_transfers_clone = Arc::clone(&file_transfers);
        let upload_dir_clone = Arc::clone(&upload_dir);
        let expected_token = args.token.clone();
        tokio::spawn(async move {
            let tls_stream = match acceptor.accept(tcp_stream).await {
                Ok(s) => s,
                Err(e) => {
                    error!("TLS handshake failed with {}: {}", peer_addr, e);
                    return;
                }
            };
            if let Err(e) = handle_client(tls_stream, file_transfers_clone, upload_dir_clone, expected_token).await {
                error!("Error handling client {}: {}", peer_addr, e);
            }
            info!("Client {} disconnected", peer_addr);
        });
    }
}

async fn handle_client<S>(
    stream: S,
    file_transfers: Arc<Mutex<HashMap<Uuid, FileTransferState>>>,
    upload_dir: Arc<String>,
    expected_token: Option<String>,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (read_half, write_half) = tokio::io::split(stream);
    let mut reader = FramedRead::new(read_half, LengthDelimitedCodec::new());
    let mut writer = FramedWrite::new(write_half, LengthDelimitedCodec::new());

    // ------------------------------------------------------------
    // Authentication handshake (if token required)
    // ------------------------------------------------------------
    if let Some(expected) = expected_token {
        // First message must be AuthRequest
        match reader.next().await {
            Some(frame_res) => {
                let bytes = frame_res?;
                let msg: Message = serde_json::from_slice(&bytes)?;
                match msg {
                    Message::AuthRequest { token } if token == expected => {
                        send_msg(&mut writer, &Message::AuthOk).await?;
                        // proceed with normal handling
                    }
                    _ => {
                        AUTH_FAILURES_TOTAL.inc();
                        send_msg(&mut writer, &Message::AuthErr { reason: "Invalid token".into() }).await.ok();
                        return Ok(());
                    }
                }
            }
            None => {
                // Connection closed before auth
                AUTH_FAILURES_TOTAL.inc();
                return Ok(());
            }
        }
    }

    while let Some(frame) = reader.next().await {
        let bytes = frame?;
        let msg: Message = serde_json::from_slice(&bytes)?;

        match msg {
            Message::Ping => {
                info!("Received ping");
                send_msg(&mut writer, &Message::Pong).await?;
            }
            Message::GetSystemMetrics => {
                info!("Received system metrics request");
                match collect_system_metrics().await {
                    Ok(metrics) => {
                        send_msg(&mut writer, &Message::SystemMetrics(metrics)).await?;
                    }
                    Err(e) => {
                        error!("Failed to collect system metrics: {}", e);
                    }
                }
            }
            Message::ExecuteCommand { command_id, program, args } => {
                info!("Executing command: {} {:?}", program, args);
                let output_result = TokioCommand::new(&program)
                    .args(&args)
                    .output()
                    .await;

                match output_result {
                    Ok(output) => {
                        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                        let exit_code = output.status.code().unwrap_or(-1);
                        let success = output.status.success();
                        let result_msg = Message::CommandResult {
                            command_id,
                            success,
                            stdout,
                            stderr,
                            exit_code,
                        };
                        if let Err(e) = send_msg(&mut writer, &result_msg).await {
                            error!("Failed to send command result: {}", e);
                        }
                    }
                    Err(e) => {
                        let result_msg = Message::CommandResult {
                            command_id,
                            success: false,
                            stdout: String::new(),
                            stderr: format!("Failed to execute command: {}", e),
                            exit_code: -1,
                        };
                        send_msg(&mut writer, &result_msg).await.ok();
                    }
                }
            }
            file_transfer_msg @ (Message::StartFileTransfer { .. }
                | Message::FileChunk { .. }
                | Message::CompleteFileTransfer { .. }) => {
                if let Err(e) = handle_file_transfer(file_transfer_msg, &mut writer, &file_transfers, &upload_dir).await {
                    error!("Failed to handle file transfer: {}", e);
                }
            }
            other => {
                info!("Received unexpected message: {:?}", other);
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

async fn handle_file_transfer<W>(
    message: Message,
    writer: &mut W,
    file_transfers: &Arc<Mutex<HashMap<Uuid, FileTransferState>>>,
    upload_dir: &str,
) -> Result<()>
where
    W: Sink<Bytes, Error = std::io::Error> + Unpin,
{
    match message {
        Message::StartFileTransfer { transfer_id, filename, total_size, chunk_size } => {
            info!("Starting file transfer: {} ({} bytes)", filename, total_size);
            
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
            send_msg(writer, &Message::FileTransferReady { transfer_id }).await?;
            
            info!("File transfer ready: {} (expecting {} chunks)", filename, expected_chunks);
        }
        
        Message::FileChunk { transfer_id, chunk_number, data, is_last_chunk: _ } => {
            info!("Received chunk {} for transfer {}", chunk_number, transfer_id);
            
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
                    error!("Received chunk for unknown transfer: {}", transfer_id);
                    return Ok(());
                }
            }
            
            // Send chunk received acknowledgment
            send_msg(writer, &Message::ChunkReceived { transfer_id, chunk_number }).await?;
            
            // If this was the last chunk or we have all chunks, complete the transfer
            if should_complete {
                complete_file_transfer(transfer_id, &filename, writer, file_transfers, upload_dir).await?;
            }
        }
        
        Message::CompleteFileTransfer { transfer_id } => {
            info!("Completing file transfer: {}", transfer_id);
            
            let filename = {
                let transfers = file_transfers.lock().await;
                if let Some(transfer_state) = transfers.get(&transfer_id) {
                    transfer_state.filename.clone()
                } else {
                    error!("Received complete request for unknown transfer: {}", transfer_id);
                    return Ok(());
                }
            };
            
            complete_file_transfer(transfer_id, &filename, writer, file_transfers, upload_dir).await?;
        }
        
        _ => {
            error!("Unexpected message in file transfer handler: {:?}", message);
        }
    }
    
    Ok(())
}

async fn complete_file_transfer<W>(
    transfer_id: Uuid,
    filename: &str,
    writer: &mut W,
    file_transfers: &Arc<Mutex<HashMap<Uuid, FileTransferState>>>,
    upload_dir: &str,
) -> Result<()>
where
    W: Sink<Bytes, Error = std::io::Error> + Unpin,
{
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
        send_msg(writer, &Message::FileTransferComplete { transfer_id, success, error }).await?;
        
        if success {
            info!("File transfer completed successfully: {}", filename);
            FILE_TRANSFERS_TOTAL.inc();
        } else {
            info!("File transfer failed: {}", filename);
        }
    }
    
    Ok(())
}
