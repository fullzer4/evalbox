//! Go execution builder.

use std::collections::hash_map::DefaultHasher;
use std::fs;
use std::hash::{Hash, Hasher};
use std::path::PathBuf;
use std::sync::LazyLock;
use std::time::Duration;

use evalbox_sandbox::{Executor, Mount, Plan};
use tempfile::TempDir;

use crate::error::{Error, Result};
use crate::output::Output;
use crate::probe::Probe;

#[cfg(any(feature = "python", feature = "go"))]
use crate::probe_cache::ProbeCache;

use super::{wrap_go_code, GoProbe};

static PROBE_CACHE: LazyLock<ProbeCache> = LazyLock::new(ProbeCache::new);

/// Builder for Go code execution.
///
/// Created by [`go::run()`](super::run). Configure with method chaining,
/// then execute with `.exec()`.
#[derive(Debug, Clone)]
pub struct GoBuilder {
    code: String,
    timeout: Duration,
    memory: u64,
    max_pids: u32,
    max_output: u64,
    network: bool,
    mounts: Vec<Mount>,
    stdin: Option<Vec<u8>>,
    env: Vec<(String, String)>,
    auto_wrap: bool,
    auto_import: bool,
    go_mod: Option<String>,
    cgo_enabled: bool,
    no_cache: bool,
    files: Vec<(String, Vec<u8>)>,
}

impl GoBuilder {
    /// Create a new Go builder for the given code.
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
            auto_wrap: true,
            auto_import: true,
            go_mod: None,
            cgo_enabled: false,
            no_cache: false,
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

    /// Enable or disable auto-wrapping with `package main` and `func main()`.
    ///
    /// Default: true
    pub fn auto_wrap(mut self, enabled: bool) -> Self {
        self.auto_wrap = enabled;
        self
    }

    /// Enable or disable auto-import detection.
    ///
    /// Default: true
    pub fn auto_import(mut self, enabled: bool) -> Self {
        self.auto_import = enabled;
        self
    }

    /// Set go.mod content for dependencies.
    pub fn go_mod(mut self, content: impl Into<String>) -> Self {
        self.go_mod = Some(content.into());
        self
    }

    /// Enable CGO.
    ///
    /// Default: false
    pub fn cgo(mut self, enabled: bool) -> Self {
        self.cgo_enabled = enabled;
        self
    }

    /// Skip cache lookup (force recompilation).
    pub fn no_cache(mut self, skip: bool) -> Self {
        self.no_cache = skip;
        self
    }

    /// Add a file to the workspace.
    pub fn file(mut self, name: impl Into<String>, content: impl Into<Vec<u8>>) -> Self {
        self.files.push((name.into(), content.into()));
        self
    }

    /// Execute the Go code and wait for completion.
    pub fn exec(self) -> Result<Output> {
        let probe = if self.cgo_enabled { GoProbe::with_cgo() } else { GoProbe::new() };

        let go_binary = probe.detect().ok_or_else(|| Error::RuntimeNotFound {
            runtime: "go".to_string(),
            searched: "$GOROOT, which go, /usr/local/go/bin/go".to_string(),
        })?;

        let runtime_info = PROBE_CACHE.get_or_probe(&probe, &go_binary)?;
        let transformed_code = wrap_go_code(&self.code, self.auto_wrap, self.auto_import);

        // Check binary cache
        let cache_key = compute_cache_key(&transformed_code, self.go_mod.as_deref(), self.cgo_enabled);
        let cache_dir = get_go_cache_dir()?.join(&cache_key);
        let cached_binary = cache_dir.join("main");

        let binary_content = if !self.no_cache && cached_binary.exists() {
            // Cache hit - read existing binary
            fs::read(&cached_binary)?
        } else {
            // Cache miss - compile in sandbox
            let binary = compile_in_sandbox(
                &go_binary,
                &transformed_code,
                self.go_mod.as_deref(),
                &self.files,
                self.cgo_enabled,
                &runtime_info,
            )?;

            // Save to cache
            fs::create_dir_all(&cache_dir)?;
            fs::write(&cached_binary, &binary)?;

            binary
        };

        // Execute in restrictive sandbox
        let mut plan = Plan::new(["/work/main".to_string()])
            .cwd("/work")
            .executable("main", binary_content)
            .timeout(self.timeout)
            .memory(self.memory)
            .max_pids(self.max_pids)
            .max_output(self.max_output)
            .network(self.network)
            .mounts(self.mounts);

        for (key, value) in self.env {
            plan = plan.env(key, value);
        }

        if let Some(stdin) = self.stdin {
            plan = plan.stdin(stdin);
        }

        let output = Executor::run(plan)?;
        Ok(output.into())
    }
}

/// Compile Go code inside a sandbox.
fn compile_in_sandbox(
    go_binary: &std::path::Path,
    code: &str,
    go_mod: Option<&str>,
    files: &[(String, Vec<u8>)],
    cgo_enabled: bool,
    runtime_info: &crate::probe::RuntimeInfo,
) -> Result<Vec<u8>> {
    // Create a temporary directory for output (mounted into sandbox)
    let output_dir = TempDir::new()?;
    let output_path = output_dir.path().join("main");

    // Build compile command
    let mut cmd = vec![
        go_binary.to_string_lossy().into_owned(),
        "build".to_string(),
        "-o".to_string(),
        "/output/main".to_string(),
        "-trimpath".to_string(),
        "main.go".to_string(),
    ];

    // For static binary without CGO
    if !cgo_enabled {
        cmd.insert(2, "-ldflags=-s -w".to_string());
    }

    let mut plan = Plan::new(cmd)
        .cwd("/work")
        .file("main.go", code.as_bytes().to_vec())
        .timeout(Duration::from_secs(120)) // Go compilation can be slow
        .memory(1024 * 1024 * 1024) // 1GB for compilation
        .env("CGO_ENABLED", if cgo_enabled { "1" } else { "0" });

    // Add go.mod if provided
    if let Some(go_mod_content) = go_mod {
        plan = plan.file("go.mod", go_mod_content.as_bytes().to_vec());
    }

    // Add user files
    for (path, content) in files {
        plan = plan.file(path, content.clone());
    }

    // Add runtime environment
    for (key, value) in &runtime_info.env {
        plan = plan.env(key, value);
    }

    // Mount GOROOT and GOMODCACHE (read-only)
    plan = plan.mounts(runtime_info.mounts.clone());

    // Mount output directory (writable) at /output
    plan = plan.mount(Mount::bind(output_dir.path(), "/output").writable());

    // Run compilation
    let output = Executor::run(plan)?;

    if !output.success() {
        return Err(Error::Compilation {
            stderr: output.stderr_str(),
            exit_code: Some(output.exit_code.unwrap_or(-1)),
        });
    }

    // Read compiled binary
    if !output_path.exists() {
        return Err(Error::Compilation {
            stderr: "go build succeeded but no binary was produced".to_string(),
            exit_code: None,
        });
    }

    Ok(fs::read(&output_path)?)
}

fn get_go_cache_dir() -> Result<PathBuf> {
    let cache_base = std::env::var("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            std::env::var("HOME")
                .map(|h| PathBuf::from(h).join(".cache"))
                .unwrap_or_else(|_| PathBuf::from("/tmp"))
        });
    Ok(cache_base.join("evalbox").join("go"))
}

fn compute_cache_key(code: &str, go_mod: Option<&str>, cgo_enabled: bool) -> String {
    let mut hasher = DefaultHasher::new();
    code.hash(&mut hasher);
    go_mod.hash(&mut hasher);
    cgo_enabled.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_defaults() {
        let builder = GoBuilder::new(r#"fmt.Println("hello")"#);
        assert!(builder.auto_wrap);
        assert!(builder.auto_import);
        assert!(!builder.cgo_enabled);
        assert!(!builder.network);
    }

    #[test]
    fn test_builder_options() {
        let builder = GoBuilder::new(r#"fmt.Println("hello")"#)
            .timeout(Duration::from_secs(10))
            .auto_wrap(false)
            .cgo(true);

        assert_eq!(builder.timeout, Duration::from_secs(10));
        assert!(!builder.auto_wrap);
        assert!(builder.cgo_enabled);
    }

    #[test]
    fn test_cache_key_deterministic() {
        let key1 = compute_cache_key("code", None, false);
        let key2 = compute_cache_key("code", None, false);
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_cache_key_different() {
        let key1 = compute_cache_key("code1", None, false);
        let key2 = compute_cache_key("code2", None, false);
        assert_ne!(key1, key2);
    }
}
