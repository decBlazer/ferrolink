use shared::{Message, SystemMetrics, MemoryInfo, DiskInfo, DEFAULT_HOST, DEFAULT_PORT};
use shared::Event;
use tokio_util::codec::{LengthDelimitedCodec, FramedRead, FramedWrite};
use bytes::Bytes;
use futures::{StreamExt, SinkExt};
use tokio::net::TcpListener;
use tokio::process::Command as TokioCommand;
use sysinfo::{System, SystemExt, DiskExt, CpuExt};
use sha2::{Sha256, Digest};
use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;
use clap::Parser;
use tracing::{info, error};
use tracing_subscriber::{EnvFilter};
use futures::Sink;
use std::fs::File;
use std::io::BufReader;
use rustls::{Certificate, PrivateKey, ServerConfig};
use rustls::server::{AllowAnyAuthenticatedClient};
use rustls::RootCertStore;
use tokio_rustls::TlsAcceptor;
use rustls_pemfile::{certs, pkcs8_private_keys, rsa_private_keys};
// Add Prometheus / Hyper imports
use hyper::{Body, Request, Response, Server};
use hyper::service::{make_service_fn, service_fn};
use once_cell::sync::Lazy;
use prometheus::{Encoder, TextEncoder, IntCounter, HistogramVec, register_int_counter, register_histogram_vec};
use sqlx::PgPool;
use serde_json::json;
use std::io::{Write};
// Build info
const BUILD_VERSION: &str = env!("CARGO_PKG_VERSION");
use lettre::{AsyncSmtpTransport, AsyncTransport, Message as EmailMessage, Tokio1Executor, transport::smtp::authentication::Credentials};
use dotenvy::dotenv;
use sqlx::{Pool, Postgres, postgres::PgPoolOptions};

// System monitor shared across requests (keeps previous CPU stats)
static SYS: Lazy<Mutex<System>> = Lazy::new(|| {
    let mut s = System::new_all();
    s.refresh_all();
    Mutex::new(s)
});

// -------------- PostgreSQL connection pool -------------------
static DB_POOL: Lazy<Pool<Postgres>> = Lazy::new(|| {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL env var missing");
    PgPoolOptions::new()
        .max_connections(5)
        .connect_lazy(&url)
        .expect("Failed to create PG pool")
});
// -------------------------------------------------------------

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

    /// Path to CA certificate to verify clients (enables mTLS if provided)
    #[arg(long)]
    ca_cert: Option<String>,

    /// Authentication token required from clients. If omitted, authentication is disabled.
    #[arg(long, env = "FERROLINK_TOKEN")]
    token: Option<String>,

    /// Port for Prometheus `/metrics` endpoint
    #[arg(long, default_value_t = 9090)]
    metrics_port: u16,

    /// SMTP server for email notifications (host:port)
    #[arg(long)]
    smtp_server: Option<String>,

    /// SMTP username
    #[arg(long)]
    smtp_user: Option<String>,

    /// SMTP password (or app password)
    #[arg(long)]
    smtp_pass: Option<String>,

    /// Comma-separated list of email addresses to notify
    #[arg(long)]
    notify_emails: Option<String>,

    /// PostgreSQL DSN for log storage (e.g. postgres://user:pass@host:5432/db)
    #[arg(long, env = "DATABASE_URL")]
    database_url: Option<String>,
}

// File transfer state tracking
struct FileTransferState {
    filename: String,
    total_size: u64,
    #[allow(dead_code)]
    chunk_size: u32,
    expected_chunks: u32,
    received_chunks: HashMap<u32, Vec<u8>>,
    start_time: std::time::Instant,
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
static BYTES_RECEIVED_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!("bytes_received_total", "Total bytes received by agent").unwrap()
});

static CMD_DURATION_SECONDS: Lazy<HistogramVec> = Lazy::new(|| {
    register_histogram_vec!(
        "command_duration_seconds",
        "Time taken to execute remote commands",
        &["program"]
    ).unwrap()
});

static FILE_TRANSFER_DURATION_SECONDS: Lazy<HistogramVec> = Lazy::new(|| {
    register_histogram_vec!(
        "file_transfer_duration_seconds",
        "Time taken to complete file transfers",
        &["filename"]
    ).unwrap()
});
// =============================================================

async fn start_metrics_server(addr: std::net::SocketAddr) -> Result<(), hyper::Error> {
    let make_svc = make_service_fn(|_conn| async {
        Ok::<_, hyper::Error>(service_fn(|req: Request<Body>| async move {
            match req.uri().path() {
                "/metrics" => {
                    let encoder = TextEncoder::new();
                    let metric_families = prometheus::gather();
                    let mut buffer = Vec::new();
                    encoder.encode(&metric_families, &mut buffer).unwrap();
                    return Ok::<_, hyper::Error>(Response::builder()
                        .status(200)
                        .header("Content-Type", encoder.format_type())
                        .body(Body::from(buffer))
                        .unwrap());
                }
                "/healthz" => {
                    return Ok::<_, hyper::Error>(Response::builder()
                        .status(200)
                        .header("Content-Type", "text/plain")
                        .body(Body::from(format!("OK {}", BUILD_VERSION)))
                        .unwrap());
                }
                _ => {}
            }
            // fallback 404
            Ok::<_, hyper::Error>(Response::builder()
                .status(404)
                .body(Body::from("Not Found"))
                .unwrap())
        }))
    });
    Server::bind(&addr).serve(make_svc).await
}

// Convenience wrapper around optional email transport
#[derive(Clone)]
#[allow(dead_code)]
struct Notifier {
    transport: Option<Arc<AsyncSmtpTransport<Tokio1Executor>>>,
    recipients: Arc<Vec<String>>,
    from: String,
}

#[allow(dead_code)]
impl Notifier {
    fn new(args: &Args) -> Self {
        if let (Some(server), Some(user), Some(pass), Some(recip)) = (&args.smtp_server, &args.smtp_user, &args.smtp_pass, &args.notify_emails) {
            let creds = Credentials::new(user.clone(), pass.clone());
            let transport = AsyncSmtpTransport::<Tokio1Executor>::relay(server)
                .expect("valid smtp")
                .credentials(creds)
                .port(server.split(':').nth(1).and_then(|p| p.parse().ok()).unwrap_or(587))
                .build();
            let recipients: Vec<String> = recip.split(',').map(|s| s.trim().to_string()).collect();
            Self { transport: Some(Arc::new(transport)), recipients: Arc::new(recipients), from: user.clone() }
        } else {
            Self { transport: None, recipients: Arc::new(vec![]), from: "noreply@example.com".into() }
        }
    }

    async fn notify(&self, subject: &str, body: &str) {
        if let Some(ref transport) = self.transport {
            for to in self.recipients.iter() {
                let email = EmailMessage::builder()
                    .from(self.from.parse().unwrap())
                    .to(to.parse().unwrap())
                    .subject(subject)
                    .body(body.to_string())
                    .unwrap();
                // fire and forget
                let _ = transport.send(email).await;
            }
        }
    }
}

// ---------- tracing writer that inserts into Postgres -----------------
#[derive(Clone)]
struct DBWriter {
    pool: PgPool,
}

impl Write for DBWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if let Ok(line) = std::str::from_utf8(buf) {
            // expected format: "2025-... INFO  message..."
            let mut parts = line.splitn(3, ' ');
            if let (Some(ts), Some(level), Some(msg)) = (parts.next(), parts.next(), parts.next()) {
                let pool = self.pool.clone();
                let ts_string = ts.to_string();
                let level_string = level.to_string();
                let msg_string = msg.trim().to_string();
                tokio::spawn(async move {
                    let _ = sqlx::query(
                        "INSERT INTO agent_logs (ts, level, message, fields) VALUES ($1,$2,$3,$4)"
                    )
                    .bind(ts_string)
                    .bind(level_string)
                    .bind(msg_string)
                    .bind(json!({}))
                    .execute(&pool)
                    .await;
                });
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
}
// -------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // optional DB pool for logging
    let db_pool_opt = if let Some(dsn) = &args.database_url {
        Some(PgPool::connect(dsn).await.expect("connect DB"))
    } else { None };

    if let Some(pool) = db_pool_opt.clone() {
        tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::from_default_env())
            .with_writer(move || DBWriter { pool: pool.clone() })
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::from_default_env())
            .init();
    }
    dotenv().ok();

    let notifier = Notifier::new(&args);
    let addr = format!("{}:{}", args.host, args.port);
    info!("Starting agent on {}", addr);
    info!("Upload directory: {}", args.upload_dir);
    
    // Build TLS acceptor
    let certs = load_certs(&args.cert_path)?;
    let key = load_private_key(&args.key_path)?;

    let builder = ServerConfig::builder().with_safe_defaults();
    let tls_config = if let Some(ca_path) = args.ca_cert.as_ref() {
        let ca_certs = load_certs(ca_path)?;
        let mut roots = RootCertStore::empty();
        for c in ca_certs { roots.add(&c)?; }
        let verifier = AllowAnyAuthenticatedClient::new(roots);
        builder
            .with_client_cert_verifier(Arc::new(verifier))
            .with_single_cert(certs, key)?
    } else {
        builder
            .with_no_client_auth()
            .with_single_cert(certs, key)?
    };
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
        let _notifier = notifier.clone();
        
        tokio::spawn(async move {
            let tls_stream = match acceptor.accept(tcp_stream).await {
                Ok(s) => s,
                Err(e) => {
                    error!("TLS handshake failed with {}: {}", peer_addr, e);
                    return;
                }
            };
            if let Err(e) = handle_client(tls_stream, file_transfers_clone, upload_dir_clone, expected_token, _notifier).await {
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
    _notifier: Notifier,
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
                let timer = CMD_DURATION_SECONDS.with_label_values(&[&program]).start_timer();
                let output_result = TokioCommand::new(&program)
                    .args(&args)
                    .output()
                    .await;
                timer.observe_duration();

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
                        // After sending CommandResult, also push an Event
                        if let Err(e) = send_msg(&mut writer, &Message::Event(Event { kind: "CommandFinished".into(), message: format!("Command {} finished (success: {})", command_id, success) })).await {
                            error!("Failed to send event: {}", e);
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
            Message::FileHashRequest { filename } => {
                let full_path = format!("{}/{}", upload_dir, filename);
                let hash_opt = match tokio::fs::read(&full_path).await {
                    Ok(bytes) => {
                        let mut hasher = Sha256::new();
                        hasher.update(&bytes);
                        let result = hasher.finalize();
                        Some(hex::encode(result))
                    }
                    Err(_) => None, // file missing or unreadable -- treat as not existing
                };

                let resp = Message::FileHashResponse { filename, hash: hash_opt };
                if let Err(e) = send_msg(&mut writer, &resp).await {
                    error!("Failed to send FileHashResponse: {}", e);
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
    // Reuse global system; need to refresh to update stats
    let mut system = SYS.lock().await;
    // Refresh CPU and memory quickly
    system.refresh_cpu();
    system.refresh_memory();
    system.refresh_disks_list();
    system.refresh_disks();

    // Average CPU usage
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
    
    // Capture disk info
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
    
    // Persist metrics to PostgreSQL (best effort). Use dynamic query to avoid
    // sqlx compile-time verification that requires a live DATABASE_URL during
    // container build.
    let _ = sqlx::query(
        "INSERT INTO system_metrics (cpu_usage_percent, mem_used_mb, mem_total_mb) VALUES ($1, $2, $3)",
    )
    .bind(cpu_usage)
    .bind((used_memory / 1024 / 1024) as i32)
    .bind((total_memory / 1024 / 1024) as i32)
    .execute(&*DB_POOL)
    .await;

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
            let expected_chunks = total_size.div_ceil(chunk_size as u64) as u32;
            
            // Create new transfer state
            let transfer_state = FileTransferState {
                filename: filename.clone(),
                total_size,
                chunk_size,
                expected_chunks,
                received_chunks: HashMap::new(),
                start_time: std::time::Instant::now(),
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
            BYTES_RECEIVED_TOTAL.inc_by(data.len() as u64);
            
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
            let duration = transfer_state.start_time.elapsed();
            FILE_TRANSFER_DURATION_SECONDS.with_label_values(&[filename]).observe(duration.as_secs_f64());
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

            // Notify client
            send_msg(writer, &Message::Event(Event { kind: "FileTransferComplete".into(), message: format!("{} uploaded successfully", filename) })).await.ok();
        } else {
            info!("File transfer failed: {}", filename);
        }
    }
    
    Ok(())
}
