//! Shell execution builder.

use std::path::PathBuf;
use std::time::Duration;

use evalbox_sandbox::{Executor, Mount, Plan};

use crate::error::Result;
use crate::output::Output;

/// Builder for shell script execution.
///
/// Created by [`shell::run()`](super::run). Configure with method chaining,
/// then execute with `.exec()`.
#[derive(Debug, Clone)]
pub struct ShellBuilder {
    script: String,
    timeout: Duration,
    memory: u64,
    max_pids: u32,
    max_output: u64,
    network: bool,
    mounts: Vec<Mount>,
    stdin: Option<Vec<u8>>,
    env: Vec<(String, String)>,
}

impl ShellBuilder {
    /// Create a new shell builder for the given script.
    pub fn new(script: &str) -> Self {
        Self {
            script: script.to_string(),
            timeout: Duration::from_secs(30),
            memory: 256 * 1024 * 1024,
            max_pids: 64,
            max_output: 16 * 1024 * 1024,
            network: false,
            mounts: Vec::new(),
            stdin: None,
            env: Vec::new(),
        }
    }

    /// Set execution timeout.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set memory limit in bytes.
    pub fn memory(mut self, bytes: u64) -> Self {
        self.memory = bytes;
        self
    }

    /// Set maximum number of processes.
    pub fn max_pids(mut self, max: u32) -> Self {
        self.max_pids = max;
        self
    }

    /// Set maximum output size in bytes.
    pub fn max_output(mut self, bytes: u64) -> Self {
        self.max_output = bytes;
        self
    }

    /// Enable or disable network access.
    ///
    /// Network is blocked by default.
    pub fn network(mut self, enabled: bool) -> Self {
        self.network = enabled;
        self
    }

    /// Add a read-only mount.
    ///
    /// # Single argument form
    /// `.with("/data")` - Mount `/data` at `/data` (same path inside/outside)
    pub fn with(mut self, path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        self.mounts.push(Mount::ro(&path));
        self
    }

    /// Add a read-only mount with different host and sandbox paths.
    pub fn with_bind(mut self, host: impl Into<PathBuf>, sandbox: impl Into<PathBuf>) -> Self {
        self.mounts.push(Mount::bind(host.into(), sandbox.into()));
        self
    }

    /// Add a read-write mount.
    ///
    /// # Single argument form
    /// `.with_rw("/output")` - Mount `/output` at `/output` (same path, read-write)
    pub fn with_rw(mut self, path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        self.mounts.push(Mount::rw(&path));
        self
    }

    /// Add a read-write mount with different host and sandbox paths.
    pub fn with_rw_bind(mut self, host: impl Into<PathBuf>, sandbox: impl Into<PathBuf>) -> Self {
        self.mounts.push(Mount::bind(host.into(), sandbox.into()).writable());
        self
    }

    /// Set standard input data.
    pub fn stdin(mut self, data: impl Into<Vec<u8>>) -> Self {
        self.stdin = Some(data.into());
        self
    }

    /// Add an environment variable.
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.push((key.into(), value.into()));
        self
    }

    /// Build the execution plan without executing.
    pub fn build(self) -> Plan {
        let mut plan = Plan::new(["sh", "-c", &self.script])
            .timeout(self.timeout)
            .memory(self.memory)
            .max_pids(self.max_pids)
            .max_output(self.max_output)
            .network(self.network)
            .mounts(self.mounts);

        if let Some(stdin) = self.stdin {
            plan = plan.stdin(stdin);
        }

        for (key, value) in self.env {
            plan = plan.env(key, value);
        }

        plan
    }

    /// Execute the shell script and wait for completion.
    pub fn exec(self) -> Result<Output> {
        let plan = self.build();
        let output = Executor::run(plan)?;
        Ok(output.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_defaults() {
        let builder = ShellBuilder::new("echo hello");
        assert_eq!(builder.script, "echo hello");
        assert!(!builder.network);
        assert_eq!(builder.timeout, Duration::from_secs(30));
    }

    #[test]
    fn test_builder_options() {
        let builder = ShellBuilder::new("echo hello")
            .timeout(Duration::from_secs(10))
            .network(true)
            .memory(512 * 1024 * 1024);

        assert_eq!(builder.timeout, Duration::from_secs(10));
        assert!(builder.network);
        assert_eq!(builder.memory, 512 * 1024 * 1024);
    }

    #[test]
    fn test_builder_mounts() {
        let builder = ShellBuilder::new("echo")
            .with("/data")
            .with_rw("/output");

        assert_eq!(builder.mounts.len(), 2);
    }

    #[test]
    fn test_build_plan() {
        let builder = ShellBuilder::new("echo hello")
            .timeout(Duration::from_secs(5))
            .network(true);

        let plan = builder.build();
        assert_eq!(plan.cmd, vec!["sh", "-c", "echo hello"]);
        assert_eq!(plan.timeout, Duration::from_secs(5));
        assert!(!plan.network_blocked);
    }
}
