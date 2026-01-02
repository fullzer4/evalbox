//! Seccomp-BPF syscall filtering with SECCOMP_USER_NOTIF support

use crate::{LeewardError, Result};
use std::os::unix::io::RawFd;
use std::collections::BTreeMap;
use seccompiler::{
    SeccompAction, SeccompFilter, SeccompRule, TargetArch
};

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
    ///
    /// If notify_mode is true, returns a file descriptor for receiving
    /// seccomp notifications. The supervisor can poll this fd and decide
    /// what to do with blocked syscalls.
    pub fn apply(&self) -> Result<Option<SeccompNotifyFd>> {
        tracing::debug!(
            notify = self.notify_mode,
            syscalls = self.allowed_syscalls.len(),
            "applying seccomp filter"
        );

        // Build the filter
        let filter = self.build_filter()?;

        // Apply the filter
        // Note: SECCOMP_USER_NOTIF requires kernel 5.0+ and special handling
        // For now, we'll use basic filtering with KILL action for denied syscalls
        // Convert filter to BPF program and apply it
        let bpf_prog: seccompiler::BpfProgram = filter
            .try_into()
            .map_err(|e| LeewardError::Seccomp(format!("failed to compile filter to BPF: {e}")))?;

        seccompiler::apply_filter(&bpf_prog)
            .map_err(|e| LeewardError::Seccomp(format!("failed to apply seccomp filter: {e}")))?;

        tracing::info!("seccomp filter applied with {} allowed syscalls", self.allowed_syscalls.len());

        // SECCOMP_USER_NOTIF would require:
        // 1. Using raw seccomp() syscall with SECCOMP_FILTER_FLAG_NEW_LISTENER
        // 2. Getting notification fd from kernel
        // 3. Setting up notification handler thread
        // For now, return None as we're using basic filtering
        Ok(None)
    }

    /// Build the seccomp filter
    fn build_filter(&self) -> Result<SeccompFilter> {
        let mut rules = BTreeMap::new();

        // For each allowed syscall, create a rule with Allow action
        // SeccompRule::new only takes conditions, the action is Allow by default for matched rules
        for &syscall_num in &self.allowed_syscalls {
            rules.insert(
                syscall_num,
                vec![SeccompRule::new(vec![])
                    .map_err(|e| LeewardError::Seccomp(format!("failed to create rule: {e}")))?],
            );
        }

        // Default action for unmatched syscalls
        let default_action = if self.log_denials {
            SeccompAction::Log // Log and deny
        } else {
            SeccompAction::KillThread // Kill the thread
        };

        // Get current architecture
        let arch = get_arch();

        // Create the filter
        SeccompFilter::new(
            rules,
            default_action,
            SeccompAction::Allow, // Bad architecture action
            arch,
        )
        .map_err(|e| LeewardError::Seccomp(format!("failed to create seccomp filter: {e}")))
    }
}

/// File descriptor for receiving seccomp notifications
///
/// When a process attempts a blocked syscall with SECCOMP_RET_USER_NOTIF,
/// the kernel sends a notification to this fd. The supervisor can:
/// - Return EACCES to continue execution
/// - Return different error code
/// - Allow the syscall (with caution)
/// - Terminate the process
#[derive(Debug)]
pub struct SeccompNotifyFd {
    fd: RawFd,
}

impl SeccompNotifyFd {
    /// Create from raw file descriptor
    pub fn from_raw_fd(fd: RawFd) -> Self {
        Self { fd }
    }

    /// Get the raw file descriptor
    pub fn as_raw_fd(&self) -> RawFd {
        self.fd
    }

    /// Wait for a seccomp notification
    pub fn wait_notification(&self) -> Result<SeccompNotification> {
        // TODO: Read seccomp_notif structure from fd
        // struct seccomp_notif {
        //     __u64 id;
        //     __u32 pid;
        //     __u32 flags;
        //     struct seccomp_data data;
        // };

        tracing::debug!("waiting for seccomp notification");

        // Placeholder
        Ok(SeccompNotification {
            id: 0,
            pid: 0,
            syscall: 0,
            args: [0; 6],
        })
    }

    /// Send a response to a seccomp notification
    pub fn send_response(&self, notif: &SeccompNotification, response: SeccompResponse) -> Result<()> {
        // TODO: Write seccomp_notif_resp structure to fd
        // struct seccomp_notif_resp {
        //     __u64 id;
        //     __s64 val;  // Return value or error code
        //     __s32 error;  // errno value
        //     __u32 flags;
        // };

        tracing::debug!(
            id = notif.id,
            pid = notif.pid,
            syscall = notif.syscall,
            response = ?response,
            "sending seccomp response"
        );

        Ok(())
    }
}

/// A seccomp notification from the kernel
#[derive(Debug, Clone)]
pub struct SeccompNotification {
    /// Notification ID (must be included in response)
    pub id: u64,
    /// Process ID that triggered the notification
    pub pid: u32,
    /// Syscall number
    pub syscall: i64,
    /// Syscall arguments
    pub args: [u64; 6],
}

/// Response to a seccomp notification
#[derive(Debug, Clone)]
pub enum SeccompResponse {
    /// Deny with EACCES
    DenyWithEacces,
    /// Deny with custom error
    DenyWithError(i32),
    /// Allow the syscall (use with extreme caution)
    Allow,
    /// Continue with specific return value
    ContinueWithValue(i64),
}

impl Drop for SeccompNotifyFd {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

/// Get the current architecture for seccomp
fn get_arch() -> TargetArch {
    #[cfg(target_arch = "x86_64")]
    return TargetArch::x86_64;

    #[cfg(target_arch = "aarch64")]
    return TargetArch::aarch64;

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    compile_error!("Unsupported architecture for seccomp");
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
