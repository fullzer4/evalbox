//! Wire protocol for daemon communication
//!
//! Supports both traditional msgpack and zero-copy shared memory modes

use crate::ExecutionResult;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Request to execute code
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecuteRequest {
    /// Python code to execute (or None if using shared memory)
    pub code: Option<String>,
    /// Shared memory slot ID (if using shared memory mode)
    pub shm_slot_id: Option<u32>,
    /// Optional timeout override
    pub timeout: Option<Duration>,
    /// Optional memory limit override
    pub memory_limit: Option<u64>,
    /// Input files (path -> content)
    pub files: Vec<(String, Vec<u8>)>,
}

/// Communication mode for the request
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum CommunicationMode {
    /// Traditional msgpack over socket
    Socket,
    /// io_uring for control, shared memory for data
    IoUring,
    /// Shared memory for both control and data
    SharedMemory,
}

/// Response from execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecuteResponse {
    /// Whether execution succeeded
    pub success: bool,
    /// Execution result (if success)
    pub result: Option<ExecutionResult>,
    /// Error message (if !success)
    pub error: Option<String>,
}

/// Request types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Request {
    /// Execute code
    Execute(ExecuteRequest),
    /// Get pool status
    Status,
    /// Ping
    Ping,
}

/// Response types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Response {
    /// Execution result
    Execute(ExecuteResponse),
    /// Pool status
    Status {
        total: usize,
        idle: usize,
        busy: usize,
    },
    /// Pong
    Pong,
    /// Error
    Error { message: String },
}

/// Encode a message to msgpack
pub fn encode<T: Serialize>(msg: &T) -> Result<Vec<u8>, rmp_serde::encode::Error> {
    rmp_serde::to_vec(msg)
}

/// Decode a message from msgpack
pub fn decode<'a, T: Deserialize<'a>>(data: &'a [u8]) -> Result<T, rmp_serde::decode::Error> {
    rmp_serde::from_slice(data)
}
