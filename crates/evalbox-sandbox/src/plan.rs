//! Sandbox execution plan.
//!
//! A `Plan` describes everything needed to run a command in the sandbox:
//! the command, environment, files, mounts, and resource limits.
//!
//! ## Example
//!
//! ```ignore
//! use evalbox_sandbox::{Plan, Mount};
//!
//! let plan = Plan::new(["python", "main.py"])
//!     .env("PYTHONPATH", "/work")
//!     .file("main.py", b"print('hello')")
//!     .timeout(Duration::from_secs(10))
//!     .memory(256 * 1024 * 1024);
//! ```
//!
//! ## Advanced Security Configuration
//!
//! ```ignore
//! use evalbox_sandbox::{Plan, Syscalls, Landlock};
//!
//! let plan = Plan::new(["python3", "-c", "code"])
//!     .syscalls(Syscalls::default().allow(libc::SYS_openat))
//!     .landlock(Landlock::default().allow_read("/etc"))
//!     .network(false);
//! ```
//!
//! ## Defaults
//!
//! | Field | Default |
//! |-------|---------|
//! | `timeout` | 30 seconds |
//! | `memory` | 256 MiB |
//! | `max_pids` | 64 processes |
//! | `max_output` | 16 MiB |
//! | `network` | false (blocked) |
//! | `cwd` | `/work` |

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::Duration;

/// Seccomp user notification mode.
///
/// Controls how the supervisor handles intercepted syscalls from the sandboxed child.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NotifyMode {
    /// No seccomp notify filter installed. Zero overhead. Default.
    #[default]
    Disabled,
    /// Supervisor logs syscalls and returns `SECCOMP_USER_NOTIF_FLAG_CONTINUE`.
    /// Minimal overhead. For debugging/auditing.
    Monitor,
    /// Supervisor intercepts FS syscalls, translates paths via `VirtualFs`,
    /// opens files at translated paths, injects fd via `SECCOMP_IOCTL_NOTIF_ADDFD`.
    Virtualize,
}

/// Mount point configuration.
///
/// This is the canonical Mount type used throughout evalbox.
#[derive(Debug, Clone)]
pub struct Mount {
    /// Path on the host filesystem.
    pub source: PathBuf,
    /// Path inside the sandbox.
    pub target: PathBuf,
    /// If false, mount is read-only (default).
    pub writable: bool,
    /// If true, executables can be run from this mount (for Landlock).
    pub executable: bool,
}

impl Mount {
    /// Read-only mount, same path inside/outside sandbox.
    pub fn ro(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        Self {
            source: path.clone(),
            target: path,
            writable: false,
            executable: true,
        }
    }

    /// Read-only mount without execute permission.
    pub fn ro_noexec(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        Self {
            source: path.clone(),
            target: path,
            writable: false,
            executable: false,
        }
    }

    /// Read-write mount, same path inside/outside sandbox.
    pub fn rw(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        Self {
            source: path.clone(),
            target: path,
            writable: true,
            executable: true,
        }
    }

    /// Mount with different host and sandbox paths (read-only by default).
    pub fn bind(source: impl Into<PathBuf>, target: impl Into<PathBuf>) -> Self {
        Self {
            source: source.into(),
            target: target.into(),
            writable: false,
            executable: true,
        }
    }

    /// Make mount writable.
    pub fn writable(mut self) -> Self {
        self.writable = true;
        self
    }

    /// Disable execute permission (for Landlock).
    pub fn noexec(mut self) -> Self {
        self.executable = false;
        self
    }
}

/// Syscall filtering configuration.
///
/// By default, a strict whitelist of ~40 safe syscalls is allowed.
/// Use this to customize the allowed syscalls for specific use cases.
///
/// ## Example
///
/// ```ignore
/// use evalbox_sandbox::Syscalls;
///
/// // Start with default whitelist, add specific syscalls
/// let syscalls = Syscalls::default()
///     .allow(libc::SYS_openat)
///     .allow(libc::SYS_socket);
///
/// // Or deny specific syscalls (removes from whitelist)
/// let syscalls = Syscalls::default()
///     .deny(libc::SYS_clone);
/// ```
#[derive(Debug, Clone, Default)]
pub struct Syscalls {
    /// Additional syscalls to allow beyond the default whitelist.
    pub allowed: HashSet<i64>,
    /// Syscalls to deny (removes from whitelist).
    pub denied: HashSet<i64>,
}

impl Syscalls {
    /// Create a new Syscalls config (default whitelist).
    pub fn new() -> Self {
        Self::default()
    }

    /// Allow a specific syscall.
    pub fn allow(mut self, syscall: i64) -> Self {
        self.allowed.insert(syscall);
        self.denied.remove(&syscall);
        self
    }

    /// Deny a specific syscall (remove from whitelist).
    pub fn deny(mut self, syscall: i64) -> Self {
        self.denied.insert(syscall);
        self.allowed.remove(&syscall);
        self
    }

    /// Allow multiple syscalls.
    pub fn allow_many(mut self, syscalls: impl IntoIterator<Item = i64>) -> Self {
        for syscall in syscalls {
            self.allowed.insert(syscall);
            self.denied.remove(&syscall);
        }
        self
    }

    /// Deny multiple syscalls.
    pub fn deny_many(mut self, syscalls: impl IntoIterator<Item = i64>) -> Self {
        for syscall in syscalls {
            self.denied.insert(syscall);
            self.allowed.remove(&syscall);
        }
        self
    }
}

/// Landlock filesystem and network access control configuration.
///
/// Landlock is a Linux security module (LSM) that provides fine-grained
/// filesystem and network access control for unprivileged processes.
///
/// ## Example
///
/// ```ignore
/// use evalbox_sandbox::Landlock;
///
/// let landlock = Landlock::default()
///     .allow_read("/etc")
///     .allow_read_write("/tmp/output")
///     .allow_execute("/usr/bin");
/// ```
#[derive(Debug, Clone, Default)]
pub struct Landlock {
    /// Paths with read access.
    pub read_paths: Vec<PathBuf>,
    /// Paths with read-write access.
    pub write_paths: Vec<PathBuf>,
    /// Paths with execute access.
    pub execute_paths: Vec<PathBuf>,
}

impl Landlock {
    /// Create a new Landlock config.
    pub fn new() -> Self {
        Self::default()
    }

    /// Allow read access to a path.
    pub fn allow_read(mut self, path: impl Into<PathBuf>) -> Self {
        self.read_paths.push(path.into());
        self
    }

    /// Allow read-write access to a path.
    pub fn allow_read_write(mut self, path: impl Into<PathBuf>) -> Self {
        self.write_paths.push(path.into());
        self
    }

    /// Allow execute access to a path.
    pub fn allow_execute(mut self, path: impl Into<PathBuf>) -> Self {
        self.execute_paths.push(path.into());
        self
    }
}

/// File to write to workspace before execution.
#[derive(Debug, Clone)]
pub struct UserFile {
    pub path: String,
    pub content: Vec<u8>,
    pub executable: bool,
}

impl UserFile {
    pub fn new(path: impl Into<String>, content: impl Into<Vec<u8>>) -> Self {
        Self {
            path: path.into(),
            content: content.into(),
            executable: false,
        }
    }

    pub fn executable(mut self) -> Self {
        self.executable = true;
        self
    }
}

/// Complete sandbox execution plan.
///
/// This is the low-level API for full control over sandbox execution.
/// Most users should use the high-level `evalbox` crate instead.
///
/// ## Example
///
/// ```ignore
/// use evalbox_sandbox::{Plan, Mount, Executor};
///
/// let plan = Plan::new(["python3", "-c", "print('hello')"])
///     .mount(Mount::ro("/usr/lib"))
///     .timeout(Duration::from_secs(60))
///     .memory(256 * 1024 * 1024)
///     .network(false);
///
/// let output = Executor::run(plan)?;
/// ```
#[derive(Debug, Clone)]
pub struct Plan {
    pub cmd: Vec<String>,
    /// Pre-resolved binary path. If set, sandbox uses this instead of resolving `cmd[0]`.
    /// This allows evalbox to do binary resolution before calling sandbox.
    pub binary_path: Option<PathBuf>,
    pub env: HashMap<String, String>,
    pub stdin: Option<Vec<u8>>,
    pub cwd: String,
    pub mounts: Vec<Mount>,
    pub user_files: Vec<UserFile>,
    pub workspace_size: u64,
    pub timeout: Duration,
    pub memory_limit: u64,
    pub max_pids: u32,
    pub max_output: u64,
    pub network_blocked: bool,
    /// Custom syscall filtering configuration.
    pub syscalls: Option<Syscalls>,
    /// Custom Landlock configuration.
    pub landlock: Option<Landlock>,
    /// Seccomp user notification mode.
    pub notify_mode: NotifyMode,
}

impl Default for Plan {
    fn default() -> Self {
        Self {
            cmd: Vec::new(),
            binary_path: None,
            env: default_env(),
            stdin: None,
            cwd: "/work".into(),
            mounts: Vec::new(),
            user_files: Vec::new(),
            workspace_size: 64 * 1024 * 1024,
            timeout: Duration::from_secs(30),
            memory_limit: 256 * 1024 * 1024,
            max_pids: 64,
            max_output: 16 * 1024 * 1024,
            network_blocked: true,
            syscalls: None,
            landlock: None,
            notify_mode: NotifyMode::Disabled,
        }
    }
}

impl Plan {
    pub fn new(cmd: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            cmd: cmd.into_iter().map(Into::into).collect(),
            ..Default::default()
        }
    }

    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.insert(key.into(), value.into());
        self
    }

    pub fn stdin(mut self, data: impl Into<Vec<u8>>) -> Self {
        self.stdin = Some(data.into());
        self
    }

    pub fn cwd(mut self, cwd: impl Into<String>) -> Self {
        self.cwd = cwd.into();
        self
    }

    pub fn mount(mut self, mount: Mount) -> Self {
        self.mounts.push(mount);
        self
    }

    /// Add multiple mounts from an iterator.
    pub fn mounts(mut self, mounts: impl IntoIterator<Item = Mount>) -> Self {
        self.mounts.extend(mounts);
        self
    }

    /// Set pre-resolved binary path.
    ///
    /// When set, the sandbox uses this path directly instead of resolving `cmd[0]`.
    /// This is used by evalbox to pre-resolve binaries before calling sandbox.
    pub fn binary_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.binary_path = Some(path.into());
        self
    }

    pub fn file(mut self, path: impl Into<String>, content: impl Into<Vec<u8>>) -> Self {
        self.user_files.push(UserFile::new(path, content));
        self
    }

    /// Add an executable binary to the workspace.
    pub fn executable(mut self, path: impl Into<String>, content: impl Into<Vec<u8>>) -> Self {
        self.user_files
            .push(UserFile::new(path, content).executable());
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn memory_limit(mut self, limit: u64) -> Self {
        self.memory_limit = limit;
        self
    }

    pub fn max_pids(mut self, max: u32) -> Self {
        self.max_pids = max;
        self
    }

    pub fn max_output(mut self, max: u64) -> Self {
        self.max_output = max;
        self
    }

    pub fn network_blocked(mut self, blocked: bool) -> Self {
        self.network_blocked = blocked;
        self
    }

    /// Enable or disable network access.
    ///
    /// This is the inverse of `network_blocked`: `network(true)` enables network,
    /// `network(false)` blocks network (default).
    pub fn network(mut self, enabled: bool) -> Self {
        self.network_blocked = !enabled;
        self
    }

    /// Set memory limit (alias for `memory_limit`).
    pub fn memory(self, limit: u64) -> Self {
        self.memory_limit(limit)
    }

    /// Set custom syscall filtering configuration.
    pub fn syscalls(mut self, syscalls: Syscalls) -> Self {
        self.syscalls = Some(syscalls);
        self
    }

    /// Set custom Landlock configuration.
    pub fn landlock(mut self, landlock: Landlock) -> Self {
        self.landlock = Some(landlock);
        self
    }

    /// Set the seccomp user notification mode.
    ///
    /// - `Disabled` (default): No notify filter, zero overhead.
    /// - `Monitor`: Log intercepted syscalls for debugging.
    /// - `Virtualize`: Full filesystem virtualization via path translation.
    pub fn notify_mode(mut self, mode: NotifyMode) -> Self {
        self.notify_mode = mode;
        self
    }

    /// Execute this plan (convenience method).
    ///
    /// Equivalent to `Executor::run(self)`.
    pub fn exec(self) -> Result<crate::Output, crate::ExecutorError> {
        crate::Executor::run(self)
    }
}

fn default_env() -> HashMap<String, String> {
    // Default PATH covers common locations on FHS and NixOS systems.
    // For NixOS, the caller (evalbox) should set PATH from SYSTEM_PATHS.
    let default_path = if std::path::Path::new("/nix/store").exists() {
        "/run/current-system/sw/bin:/nix/var/nix/profiles/default/bin:/usr/bin:/bin"
    } else {
        "/usr/local/bin:/usr/bin:/bin"
    };

    HashMap::from([
        ("PATH".into(), default_path.into()),
        ("HOME".into(), "/home".into()),
        ("USER".into(), "sandbox".into()),
        ("LANG".into(), "C.UTF-8".into()),
        ("LC_ALL".into(), "C.UTF-8".into()),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_new() {
        let plan = Plan::new(["echo", "hello"]);
        assert_eq!(plan.cmd, vec!["echo", "hello"]);
        assert!(plan.network_blocked);
    }

    #[test]
    fn plan_builder() {
        let plan = Plan::new(["python", "main.py"])
            .env("PYTHONPATH", "/work")
            .stdin(b"input".to_vec())
            .timeout(Duration::from_secs(10))
            .file("main.py", b"print('hello')");

        assert_eq!(plan.env.get("PYTHONPATH"), Some(&"/work".into()));
        assert_eq!(plan.stdin, Some(b"input".to_vec()));
        assert_eq!(plan.timeout, Duration::from_secs(10));
        assert_eq!(plan.user_files.len(), 1);
    }

    #[test]
    fn plan_network_methods() {
        let plan = Plan::new(["echo"]).network(true);
        assert!(!plan.network_blocked);

        let plan = Plan::new(["echo"]).network(false);
        assert!(plan.network_blocked);
    }

    #[test]
    fn plan_syscalls_config() {
        let syscalls = Syscalls::default().allow(1).allow(2).deny(3);

        assert!(syscalls.allowed.contains(&1));
        assert!(syscalls.allowed.contains(&2));
        assert!(syscalls.denied.contains(&3));
    }

    #[test]
    fn plan_landlock_config() {
        let landlock = Landlock::new().allow_read("/etc").allow_read_write("/tmp");

        assert_eq!(landlock.read_paths.len(), 1);
        assert_eq!(landlock.write_paths.len(), 1);
    }
}
