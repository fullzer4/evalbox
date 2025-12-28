//! Daemon configuration

use leeward_core::SandboxConfig;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Configuration for the daemon
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonConfig {
    /// Path to Unix socket
    pub socket_path: PathBuf,

    /// Number of workers in the pool
    pub num_workers: usize,

    /// Recycle workers after this many executions
    pub recycle_after: u64,

    /// Sandbox configuration for workers
    pub sandbox_config: SandboxConfig,

    /// Enable metrics endpoint
    pub metrics_enabled: bool,

    /// Metrics port
    pub metrics_port: u16,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            socket_path: PathBuf::from("/var/run/leeward.sock"),
            num_workers: 4,
            recycle_after: 100,
            sandbox_config: SandboxConfig::default(),
            metrics_enabled: true,
            metrics_port: 9090,
        }
    }
}
