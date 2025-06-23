use serde::{Deserialize, Serialize};

// The most basic message types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Message {
    Ping,
    Pong,
}

// Protocol constants
pub const DEFAULT_PORT: u16 = 8080;
pub const DEFAULT_HOST: &str = "127.0.0.1"; 