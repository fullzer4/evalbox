//! Sandbox configuration

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

/// Configuration for a sandbox instance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxConfig {
    /// Path to Python interpreter
    pub python_path: PathBuf,

    /// Additional paths to bind mount read-only
    pub ro_binds: Vec<PathBuf>,

    /// Paths to bind mount read-write
    pub rw_binds: Vec<PathBuf>,

    /// Memory limit in bytes
    pub memory_limit: u64,

    /// CPU limit as percentage (0-100)
    pub cpu_limit: u32,

    /// Maximum execution time
    pub timeout: Duration,

    /// Maximum number of processes/threads
    pub max_pids: u32,

    /// Allow network access
    pub allow_network: bool,

    /// Working directory inside sandbox
    pub workdir: PathBuf,

    /// Environment variables
    pub env: Vec<(String, String)>,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            python_path: PathBuf::from("/usr/bin/python3"),
            ro_binds: vec![
                PathBuf::from("/usr"),
                PathBuf::from("/lib"),
                PathBuf::from("/lib64"),
            ],
            rw_binds: vec![],
            memory_limit: 256 * 1024 * 1024, // 256MB
            cpu_limit: 100,
            timeout: Duration::from_secs(30),
            max_pids: 32,
            allow_network: false,
            workdir: PathBuf::from("/home/sandbox"),
            env: vec![
                ("PATH".into(), "/usr/bin:/bin".into()),
                ("HOME".into(), "/home/sandbox".into()),
                ("TMPDIR".into(), "/tmp".into()),
            ],
        }
    }
}

impl SandboxConfig {
    /// Create a new config builder
    #[must_use]
    pub fn builder() -> SandboxConfigBuilder {
        SandboxConfigBuilder::default()
    }
}

/// Builder for SandboxConfig
#[derive(Debug, Default)]
pub struct SandboxConfigBuilder {
    config: SandboxConfig,
}

impl SandboxConfigBuilder {
    #[must_use]
    pub fn python_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.config.python_path = path.into();
        self
    }

    #[must_use]
    pub fn memory_limit(mut self, bytes: u64) -> Self {
        self.config.memory_limit = bytes;
        self
    }

    #[must_use]
    pub fn memory_limit_mb(self, mb: u64) -> Self {
        self.memory_limit(mb * 1024 * 1024)
    }

    #[must_use]
    pub fn cpu_limit(mut self, percent: u32) -> Self {
        self.config.cpu_limit = percent.min(100);
        self
    }

    #[must_use]
    pub fn timeout(mut self, duration: Duration) -> Self {
        self.config.timeout = duration;
        self
    }

    #[must_use]
    pub fn timeout_secs(self, secs: u64) -> Self {
        self.timeout(Duration::from_secs(secs))
    }

    #[must_use]
    pub fn allow_network(mut self, allow: bool) -> Self {
        self.config.allow_network = allow;
        self
    }

    #[must_use]
    pub fn ro_bind(mut self, path: impl Into<PathBuf>) -> Self {
        self.config.ro_binds.push(path.into());
        self
    }

    #[must_use]
    pub fn rw_bind(mut self, path: impl Into<PathBuf>) -> Self {
        self.config.rw_binds.push(path.into());
        self
    }

    #[must_use]
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.config.env.push((key.into(), value.into()));
        self
    }

    #[must_use]
    pub fn build(self) -> SandboxConfig {
        self.config
    }
}
