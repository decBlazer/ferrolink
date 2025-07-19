use serde::{Deserialize, Serialize};
use uuid::Uuid;

// Message types for our protocol
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Message {
    Ping,
    Pong,
    
    // System monitoring messages
    GetSystemMetrics,
    SystemMetrics(SystemMetrics),
    
    // File transfer messages
    StartFileTransfer {
        transfer_id: Uuid,
        filename: String,
        total_size: u64,
        chunk_size: u32,
    },
    FileTransferReady {
        transfer_id: Uuid,
    },
    FileChunk {
        transfer_id: Uuid,
        chunk_number: u32,
        data: Vec<u8>,
        is_last_chunk: bool,
    },
    ChunkReceived {
        transfer_id: Uuid,
        chunk_number: u32,
    },
    CompleteFileTransfer {
        transfer_id: Uuid,
    },
    FileTransferComplete {
        transfer_id: Uuid,
        success: bool,
        error: Option<String>,
    },
    // File synchronization: hash check
    /// Request SHA-256 hash of a file already present on the agent (its upload directory)
    FileHashRequest {
        filename: String,
    },
    /// Response with the hex-encoded SHA-256 hash if the file exists; `None` if missing
    FileHashResponse {
        filename: String,
        hash: Option<String>,
    },
    // Asynchronous event pushed by agent
    Event(Event),
    // Authentication messages
    AuthRequest { token: String },
    AuthOk,
    AuthErr { reason: String },
    
    // Remote command execution
    /// Execute a program with optional arguments on the agent
    ExecuteCommand {
        command_id: Uuid,
        program: String,
        args: Vec<String>,
    },
    /// Result of a previously requested command execution
    CommandResult {
        command_id: Uuid,
        success: bool,
        stdout: String,
        stderr: String,
        exit_code: i32,
    },
}

// Event information sent by agent to inform client about system or task status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub kind: String,   // e.g. "CommandFinished", "FileTransferComplete"
    pub message: String,
}

// Data structure for system monitoring information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemMetrics {
    pub cpu_usage_percent: f64,
    pub memory: MemoryInfo,
    pub disks: Vec<DiskInfo>,
}

// Memory usage information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryInfo {
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub available_bytes: u64,
    pub usage_percent: f64,
}

// Disk usage information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskInfo {
    pub name: String,
    pub mount_point: String,
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub available_bytes: u64,
    pub usage_percent: f64,
}

// Protocol constants
pub const DEFAULT_PORT: u16 = 8080;
pub const DEFAULT_HOST: &str = "127.0.0.1";