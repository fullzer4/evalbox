//! Security lockdown for sandboxed processes.
//!
//! Applies all security restrictions to the child process after `pivot_root`.
//! The order of operations is critical for security:
//!
//! 1. **Landlock** - Filesystem and network access control (ABI 4+)
//! 2. **Seccomp** - Syscall whitelist filter (BPF)
//! 3. **Rlimits** - Resource limits (memory, CPU, files, processes)
//! 4. **Capabilities** - Drop all capabilities, set `NO_NEW_PRIVS`
//! 5. **Close FDs** - Close all file descriptors except stdin/stdout/stderr
//!
//! After lockdown, the process cannot:
//! - Access files outside allowed paths
//! - Make network connections (if landlock ABI >= 4)
//! - Call restricted syscalls (ptrace, mount, reboot, etc.)
//! - Exceed resource limits
//! - Gain new privileges

use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use evalbox_sys::landlock::{
    self, LANDLOCK_ACCESS_FS_EXECUTE, LANDLOCK_ACCESS_FS_MAKE_DIR, LANDLOCK_ACCESS_FS_MAKE_REG,
    LANDLOCK_ACCESS_FS_READ_DIR, LANDLOCK_ACCESS_FS_READ_FILE, LANDLOCK_ACCESS_FS_REMOVE_DIR,
    LANDLOCK_ACCESS_FS_REMOVE_FILE, LANDLOCK_ACCESS_FS_TRUNCATE, LANDLOCK_ACCESS_FS_WRITE_FILE,
    LandlockPathBeneathAttr, LandlockRulesetAttr, fs_access_for_abi, landlock_add_rule_path,
    landlock_create_ruleset, landlock_restrict_self, net_access_for_abi,
};
use evalbox_sys::last_errno;
use evalbox_sys::seccomp::{
    DEFAULT_WHITELIST, SockFprog, build_whitelist_filter, seccomp_set_mode_filter,
};
use rustix::io::Errno;
use thiserror::Error;

use super::rootfs::apply_rlimits;
use crate::plan::Plan;

/// Error during security lockdown.
#[derive(Debug, Error)]
pub enum LockdownError {
    #[error("landlock: {0}")]
    Landlock(Errno),

    #[error("seccomp: {0}")]
    Seccomp(Errno),

    #[error("rlimit: {0}")]
    Rlimit(Errno),

    #[error("capability: {0}")]
    Capability(Errno),

    #[error("close fds: {0}")]
    CloseFds(Errno),
}

pub fn lockdown(
    plan: &Plan,
    workspace_path: Option<&Path>,
    extra_readonly_paths: &[&str],
) -> Result<(), LockdownError> {
    apply_landlock(plan, workspace_path, extra_readonly_paths)?;
    apply_seccomp()?;
    apply_rlimits(plan).map_err(LockdownError::Rlimit)?;
    drop_all_caps()?;
    close_extra_fds()?;
    Ok(())
}

fn apply_landlock(
    plan: &Plan,
    workspace_path: Option<&Path>,
    extra_readonly_paths: &[&str],
) -> Result<(), LockdownError> {
    let abi = match landlock::landlock_abi_version() {
        Ok(v) => v,
        Err(_) => return Ok(()), // Landlock not available
    };

    let fs_access = fs_access_for_abi(abi);
    let net_access = if plan.network_blocked && abi >= 4 {
        net_access_for_abi(abi)
    } else {
        0
    };

    let attr = LandlockRulesetAttr {
        handled_access_fs: fs_access,
        handled_access_net: net_access,
    };
    let ruleset_fd = landlock_create_ruleset(&attr).map_err(LockdownError::Landlock)?;

    let read_access =
        LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;
    let write_access = read_access
        | LANDLOCK_ACCESS_FS_WRITE_FILE
        | LANDLOCK_ACCESS_FS_MAKE_REG
        | LANDLOCK_ACCESS_FS_MAKE_DIR
        | LANDLOCK_ACCESS_FS_REMOVE_FILE
        | LANDLOCK_ACCESS_FS_REMOVE_DIR
        | LANDLOCK_ACCESS_FS_TRUNCATE;

    // Read-only paths from plan.mounts (pre-computed by evalbox, includes system paths)
    for mount in &plan.mounts {
        if !mount.writable {
            let access = if mount.executable {
                read_access
            } else {
                read_access & !LANDLOCK_ACCESS_FS_EXECUTE
            };
            add_path_rule(&ruleset_fd, &mount.target, access);
        }
    }

    for path in extra_readonly_paths {
        add_path_rule(&ruleset_fd, path, read_access);
    }

    // Pre-pivot_root workspace path
    if let Some(ws_path) = workspace_path {
        add_path_rule(&ruleset_fd, ws_path, write_access);
    }

    // Writable paths
    for path in ["/work", "/tmp", "/home"] {
        add_path_rule(&ruleset_fd, path, write_access);
    }

    // Proc (read-only)
    add_path_rule(&ruleset_fd, "/proc", read_access);

    // Dev (read + write for /dev/null etc.)
    add_path_rule(
        &ruleset_fd,
        "/dev",
        read_access | LANDLOCK_ACCESS_FS_WRITE_FILE,
    );

    landlock_restrict_self(&ruleset_fd).map_err(LockdownError::Landlock)
}

/// Add a path rule to the Landlock ruleset.
///
/// Errors are logged to stderr but not propagated - the path simply won't be
/// accessible in the sandbox. This is intentional: missing paths (like /nix/store
/// on non-NixOS) should not prevent sandbox creation.
fn add_path_rule(ruleset_fd: &OwnedFd, path: impl AsRef<Path>, access: u64) {
    let path = path.as_ref();
    let fd = match open_path(path) {
        Ok(fd) => fd,
        Err(_) => return, // Path doesn't exist, skip silently
    };

    let rule = LandlockPathBeneathAttr {
        allowed_access: access,
        parent_fd: fd.as_raw_fd(),
    };
    if let Err(e) = landlock_add_rule_path(ruleset_fd, &rule) {
        // Log but don't fail - path won't be accessible in sandbox
        eprintln!("warning: landlock rule for {path:?} failed: {e}");
    }
}

#[inline]
fn open_path(path: impl AsRef<Path>) -> Result<OwnedFd, Errno> {
    let path_c = CString::new(path.as_ref().as_os_str().as_bytes()).map_err(|_| Errno::INVAL)?;
    let fd = unsafe { libc::open(path_c.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if fd < 0 {
        Err(last_errno())
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

fn apply_seccomp() -> Result<(), LockdownError> {
    let filter = build_whitelist_filter(DEFAULT_WHITELIST);
    let fprog = SockFprog {
        len: filter.len() as u16,
        filter: filter.as_ptr(),
    };
    unsafe { seccomp_set_mode_filter(&fprog) }.map_err(LockdownError::Seccomp)
}

fn drop_all_caps() -> Result<(), LockdownError> {
    unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        );
        for cap in 0..64 {
            libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0);
        }
    }

    let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if ret != 0 {
        Err(LockdownError::Capability(last_errno()))
    } else {
        Ok(())
    }
}

fn close_extra_fds() -> Result<(), LockdownError> {
    let mut fds_to_close = Vec::new();

    if let Ok(entries) = std::fs::read_dir("/proc/self/fd") {
        for entry in entries.flatten() {
            if let Ok(fd) = entry.file_name().to_string_lossy().parse::<RawFd>() {
                if fd > 2 {
                    fds_to_close.push(fd);
                }
            }
        }
    }

    for fd in fds_to_close {
        unsafe { libc::close(fd) };
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_path_valid() {
        assert!(open_path("/tmp").is_ok());
    }
}
