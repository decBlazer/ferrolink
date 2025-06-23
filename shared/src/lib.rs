use serde::{Deserialize, Serialize};

// Message types for our protocol
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Message {
    Ping,
    Pong,
    
    // System monitoring messages
    GetSystemMetrics,
    SystemMetrics(SystemMetrics),
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