//! Seccomp-BPF syscall filtering

use crate::{LeewardError, Result};

/// Configuration for seccomp filtering
#[derive(Debug, Clone)]
pub struct SeccompConfig {
    /// Use NOTIFY mode instead of KILL (allows supervisor intervention)
    pub notify_mode: bool,
    /// Syscalls to allow
    pub allowed_syscalls: Vec<i64>,
    /// Log denied syscalls before killing
    pub log_denials: bool,
}

impl Default for SeccompConfig {
    fn default() -> Self {
        Self {
            notify_mode: true,
            allowed_syscalls: default_python_syscalls(),
            log_denials: true,
        }
    }
}

impl SeccompConfig {
    /// Apply the seccomp filter to the current process
    pub fn apply(&self) -> Result<()> {
        // TODO: Build and apply BPF filter using seccompiler
        tracing::debug!(
            notify = self.notify_mode,
            syscalls = self.allowed_syscalls.len(),
            "applying seccomp filter"
        );
        Ok(())
    }
}

/// Default syscalls needed for Python to run
fn default_python_syscalls() -> Vec<i64> {
    vec![
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_close,
        libc::SYS_fstat,
        libc::SYS_lseek,
        libc::SYS_mmap,
        libc::SYS_mprotect,
        libc::SYS_munmap,
        libc::SYS_brk,
        libc::SYS_rt_sigaction,
        libc::SYS_rt_sigprocmask,
        libc::SYS_ioctl,
        libc::SYS_access,
        libc::SYS_dup,
        libc::SYS_dup2,
        libc::SYS_getpid,
        libc::SYS_getuid,
        libc::SYS_getgid,
        libc::SYS_geteuid,
        libc::SYS_getegid,
        libc::SYS_fcntl,
        libc::SYS_openat,
        libc::SYS_newfstatat,
        libc::SYS_exit,
        libc::SYS_exit_group,
        libc::SYS_futex,
        libc::SYS_getrandom,
        libc::SYS_clock_gettime,
        libc::SYS_clock_nanosleep,
    ]
}
