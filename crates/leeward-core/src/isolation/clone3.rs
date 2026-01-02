//! clone3 syscall wrapper with CLONE_INTO_CGROUP support

use crate::{LeewardError, Result};
use libc::pid_t;
use std::os::unix::io::RawFd;

/// clone3 clone_args structure (from linux/sched.h)
#[repr(C)]
#[derive(Debug, Default)]
pub struct CloneArgs {
    /// Flags for the new process
    pub flags: u64,
    /// File descriptor for pidfd
    pub pidfd: u64,
    /// Signal to deliver on child termination
    pub exit_signal: u64,
    /// Stack pointer (0 = copy parent stack)
    pub stack: u64,
    /// Stack size (0 if using parent stack)
    pub stack_size: u64,
    /// TLS pointer
    pub tls: u64,
    /// Pointer to set_tid array
    pub set_tid: u64,
    /// Size of set_tid array
    pub set_tid_size: u64,
    /// File descriptor for cgroup
    pub cgroup: u64,
}

/// clone3 syscall number
const SYS_CLONE3: i64 = 435;

/// CLONE_INTO_CGROUP flag (requires Linux >= 5.7)
pub const CLONE_INTO_CGROUP: u64 = 0x200000000;

/// Wrapper around the clone3 syscall
///
/// # Safety
/// This function makes a raw syscall and forks the process
pub unsafe fn clone3(args: &CloneArgs) -> Result<pid_t> {
    // SAFETY: Making clone3 syscall with valid args
    let ret = unsafe {
        libc::syscall(
            SYS_CLONE3,
            args as *const CloneArgs,
            std::mem::size_of::<CloneArgs>(),
        )
    };

    if ret == -1 {
        return Err(LeewardError::Namespace(format!(
            "clone3 failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    Ok(ret as pid_t)
}

/// Helper to create a pre-forked worker with namespaces and cgroup
pub fn clone_worker(
    cgroup_fd: RawFd,
    namespace_flags: u64,
    child_fn: impl FnOnce() -> Result<()>,
) -> Result<pid_t> {
    let mut flags = namespace_flags;

    // Only use CLONE_INTO_CGROUP if we have a valid fd
    if cgroup_fd >= 0 {
        flags |= CLONE_INTO_CGROUP;
    }

    let args = CloneArgs {
        flags,
        exit_signal: libc::SIGCHLD as u64,
        cgroup: if cgroup_fd >= 0 { cgroup_fd as u64 } else { 0 },
        ..Default::default()
    };

    // SAFETY: We're forking the process with clone3
    let pid = unsafe { clone3(&args)? };

    if pid == 0 {
        // Child process
        drop(child_fn());
        // SAFETY: Exiting child process
        unsafe { libc::_exit(0) };
    }

    // Parent process
    Ok(pid)
}
