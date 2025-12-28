//! Execution result types

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Result of a sandboxed code execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionResult {
    /// Exit code of the process
    pub exit_code: i32,

    /// Standard output
    pub stdout: Vec<u8>,

    /// Standard error
    pub stderr: Vec<u8>,

    /// Execution duration
    pub duration: Duration,

    /// Peak memory usage in bytes
    pub memory_peak: u64,

    /// CPU time used in microseconds
    pub cpu_time_us: u64,

    /// Whether the process was killed due to timeout
    pub timed_out: bool,

    /// Whether the process was killed due to memory limit
    pub oom_killed: bool,
}

impl ExecutionResult {
    /// Get stdout as UTF-8 string, lossy conversion
    #[must_use]
    pub fn stdout_str(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }

    /// Get stderr as UTF-8 string, lossy conversion
    #[must_use]
    pub fn stderr_str(&self) -> String {
        String::from_utf8_lossy(&self.stderr).into_owned()
    }

    /// Check if execution was successful (exit code 0, no timeout, no OOM)
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.exit_code == 0 && !self.timed_out && !self.oom_killed
    }
}

impl Default for ExecutionResult {
    fn default() -> Self {
        Self {
            exit_code: -1,
            stdout: Vec::new(),
            stderr: Vec::new(),
            duration: Duration::ZERO,
            memory_peak: 0,
            cpu_time_us: 0,
            timed_out: false,
            oom_killed: false,
        }
    }
}
