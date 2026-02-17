//! Python execution builder.

use std::path::PathBuf;
use std::sync::LazyLock;
use std::time::Duration;

use evalbox_sandbox::{Executor, Mount, Plan};

use crate::error::{Error, Result};
use crate::output::Output;
use crate::probe::Probe;

#[cfg(any(feature = "python", feature = "go"))]
use crate::probe_cache::ProbeCache;

use super::PythonProbe;

static PROBE_CACHE: LazyLock<ProbeCache> = LazyLock::new(ProbeCache::new);

/// Builder for Python code execution.
///
/// Created by [`python::run()`](super::run). Configure with method chaining,
/// then execute with `.exec()`.
#[derive(Debug, Clone)]
pub struct PythonBuilder {
    code: String,
    timeout: Duration,
    memory: u64,
    max_pids: u32,
    max_output: u64,
    network: bool,
    mounts: Vec<Mount>,
    stdin: Option<Vec<u8>>,
    env: Vec<(String, String)>,
    venv: Option<PathBuf>,
    files: Vec<(String, Vec<u8>)>,
}

impl PythonBuilder {
    /// Create a new Python builder for the given code.
    pub fn new(code: &str) -> Self {
        Self {
            code: code.to_string(),
            timeout: Duration::from_secs(30),
            memory: 256 * 1024 * 1024,
            max_pids: 64,
            max_output: 16 * 1024 * 1024,
            network: false,
            mounts: Vec::new(),
            stdin: None,
            env: Vec::new(),
            venv: None,
            files: Vec::new(),
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
    pub fn with_rw(mut self, path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        self.mounts.push(Mount::rw(&path));
        self
    }

    /// Add a read-write mount with different host and sandbox paths.
    pub fn with_rw_bind(mut self, host: impl Into<PathBuf>, sandbox: impl Into<PathBuf>) -> Self {
        self.mounts
            .push(Mount::bind(host.into(), sandbox.into()).writable());
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

    /// Use a specific virtualenv.
    pub fn venv(mut self, path: impl Into<PathBuf>) -> Self {
        self.venv = Some(path.into());
        self
    }

    /// Add a file to the workspace.
    pub fn file(mut self, name: impl Into<String>, content: impl Into<Vec<u8>>) -> Self {
        self.files.push((name.into(), content.into()));
        self
    }

    /// Execute the Python code and wait for completion.
    pub fn exec(self) -> Result<Output> {
        let probe = PythonProbe::new();

        // Determine Python binary
        let (venv_path, binary) = if let Some(venv) = &self.venv {
            let venv_python = venv.join("bin/python3");
            let binary = if venv_python.exists() {
                venv_python
            } else {
                venv.join("bin/python")
            };
            (Some(venv.clone()), binary)
        } else {
            let binary = probe.detect().ok_or_else(|| Error::RuntimeNotFound {
                runtime: "python".to_string(),
                searched: "$VIRTUAL_ENV, which python3, /usr/bin/python3".to_string(),
            })?;
            (None, binary)
        };

        // Probe runtime
        let runtime_info = PROBE_CACHE.get_or_probe(&probe, &binary)?;

        // Build plan
        let mut plan = Plan::new([
            binary.to_string_lossy().into_owned(),
            "-c".to_string(),
            self.code.clone(),
        ])
        .cwd("/work")
        .timeout(self.timeout)
        .memory(self.memory)
        .max_pids(self.max_pids)
        .max_output(self.max_output)
        .network(self.network)
        .mounts(runtime_info.mounts.clone())
        .env("PYTHONDONTWRITEBYTECODE", "1");

        // Add runtime env
        for (key, value) in &runtime_info.env {
            plan = plan.env(key, value);
        }

        // Add venv mount
        if let Some(venv) = venv_path {
            plan = plan.mount(Mount::ro(&venv));
        }

        // Add user mounts
        plan = plan.mounts(self.mounts);

        // Add user files
        for (name, content) in self.files {
            plan = plan.file(name, content);
        }

        // Add user env
        for (key, value) in self.env {
            plan = plan.env(key, value);
        }

        // Add stdin
        if let Some(stdin) = self.stdin {
            plan = plan.stdin(stdin);
        }

        let output = Executor::run(plan)?;
        Ok(output.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_defaults() {
        let builder = PythonBuilder::new("print('hello')");
        assert_eq!(builder.code, "print('hello')");
        assert!(!builder.network);
        assert_eq!(builder.timeout, Duration::from_secs(30));
    }

    #[test]
    fn test_builder_options() {
        let builder = PythonBuilder::new("print('hello')")
            .timeout(Duration::from_secs(10))
            .network(true)
            .memory(512 * 1024 * 1024);

        assert_eq!(builder.timeout, Duration::from_secs(10));
        assert!(builder.network);
        assert_eq!(builder.memory, 512 * 1024 * 1024);
    }

    #[test]
    fn test_builder_venv() {
        let builder = PythonBuilder::new("import numpy").venv("/path/to/.venv");

        assert_eq!(builder.venv, Some(PathBuf::from("/path/to/.venv")));
    }
}
