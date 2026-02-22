//! Security lockdown for sandboxed processes.
//!
//! Applies all security restrictions to the child process.
//! The order of operations is critical for security:
//!
//! 0. **`NO_NEW_PRIVS`** - Required before Landlock and seccomp
//! 1. **Landlock v5** - Filesystem, network, signal, and IPC access control
//! 2. **Rlimits** - Resource limits (memory, CPU, files, processes)
//! 3. **Securebits** - Lock capability state permanently
//! 4. **Capabilities** - Drop all capabilities
//!
//! Note: Seccomp filters and fd closing are handled separately in `child_process()`
//! because the notify filter must return a listener fd that gets sent to the parent.
//!
//! After lockdown, the process cannot:
//! - Access files outside allowed paths
//! - Make network connections (if network blocked, requires Landlock ABI 4+)
//! - Send signals to processes outside the sandbox (Landlock ABI 5+)
//! - Connect to abstract unix sockets outside the sandbox (Landlock ABI 5+)
//! - Exceed resource limits
//! - Gain new privileges

use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use evalbox_sys::landlock::{
    self, LANDLOCK_ACCESS_FS_EXECUTE, LANDLOCK_ACCESS_FS_MAKE_DIR, LANDLOCK_ACCESS_FS_MAKE_FIFO,
    LANDLOCK_ACCESS_FS_MAKE_REG, LANDLOCK_ACCESS_FS_MAKE_SYM, LANDLOCK_ACCESS_FS_READ_DIR,
    LANDLOCK_ACCESS_FS_READ_FILE, LANDLOCK_ACCESS_FS_REMOVE_DIR, LANDLOCK_ACCESS_FS_REMOVE_FILE,
    LANDLOCK_ACCESS_FS_TRUNCATE, LANDLOCK_ACCESS_FS_WRITE_FILE, LandlockPathBeneathAttr,
    LandlockRulesetAttr, fs_access_for_abi, landlock_add_rule_path, landlock_create_ruleset,
    landlock_restrict_self, net_access_for_abi, scope_for_abi,
};
use evalbox_sys::last_errno;
use rustix::io::Errno;
use thiserror::Error;

use super::rlimits::apply_rlimits;
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

    #[error("securebits: {0}")]
    Securebits(Errno),
}

/// Apply security lockdown to the current process.
///
/// `workspace_root` is the real absolute path to the workspace directory
/// (no `pivot_root`, so we use real paths).
///
/// `extra_readonly_paths` are additional paths that should be readable
/// (e.g., resolved binary mount paths).
pub fn lockdown(
    plan: &Plan,
    workspace_root: &Path,
    extra_readonly_paths: &[&str],
) -> Result<(), LockdownError> {
    // NO_NEW_PRIVS must be set before landlock_restrict_self and seccomp.
    set_no_new_privs()?;
    apply_landlock_v5(plan, workspace_root, extra_readonly_paths)?;
    apply_rlimits(plan).map_err(LockdownError::Rlimit)?;
    apply_securebits()?;
    drop_all_caps()?;
    Ok(())
}

fn apply_landlock_v5(
    plan: &Plan,
    workspace_root: &Path,
    extra_readonly_paths: &[&str],
) -> Result<(), LockdownError> {
    let abi = match landlock::landlock_abi_version() {
        Ok(v) => v,
        Err(_) => return Ok(()), // Landlock not available
    };

    if abi < 5 {
        eprintln!("warning: landlock ABI {abi} < 5, signal/IPC scoping unavailable");
    }

    let fs_access = fs_access_for_abi(abi);
    let net_access = if plan.network_blocked && abi >= 4 {
        net_access_for_abi(abi)
    } else {
        0
    };
    let scoped = scope_for_abi(abi);

    let attr = LandlockRulesetAttr {
        handled_access_fs: fs_access,
        handled_access_net: net_access,
        scoped,
    };
    let ruleset_fd = landlock_create_ruleset(&attr).map_err(LockdownError::Landlock)?;

    let read_access =
        LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;
    let write_access = read_access
        | LANDLOCK_ACCESS_FS_WRITE_FILE
        | LANDLOCK_ACCESS_FS_MAKE_REG
        | LANDLOCK_ACCESS_FS_MAKE_DIR
        | LANDLOCK_ACCESS_FS_MAKE_SYM
        | LANDLOCK_ACCESS_FS_MAKE_FIFO
        | LANDLOCK_ACCESS_FS_REMOVE_FILE
        | LANDLOCK_ACCESS_FS_REMOVE_DIR
        | LANDLOCK_ACCESS_FS_TRUNCATE;

    // Read-only mounts from plan (system paths computed by evalbox or user-specified)
    for mount in &plan.mounts {
        if !mount.writable {
            let access = if mount.executable {
                read_access
            } else {
                read_access & !LANDLOCK_ACCESS_FS_EXECUTE
            };
            add_path_rule(&ruleset_fd, &mount.source, access);
        }
    }

    // Extra readonly paths (resolved binary mounts)
    for path in extra_readonly_paths {
        add_path_rule(&ruleset_fd, path, read_access);
    }

    // Writable workspace paths (real absolute paths, no pivot_root)
    add_path_rule(&ruleset_fd, workspace_root.join("work"), write_access);
    add_path_rule(&ruleset_fd, workspace_root.join("tmp"), write_access);
    add_path_rule(&ruleset_fd, workspace_root.join("home"), write_access);

    // System paths (read-only with execute)
    for path in ["/usr", "/bin", "/lib", "/lib64", "/etc"] {
        add_path_rule(&ruleset_fd, path, read_access);
    }

    // NixOS store
    if Path::new("/nix/store").exists() {
        add_path_rule(&ruleset_fd, "/nix/store", read_access);
    }
    if Path::new("/run/current-system").exists() {
        add_path_rule(&ruleset_fd, "/run/current-system", read_access);
    }

    // Proc (read-only)
    add_path_rule(
        &ruleset_fd,
        "/proc",
        read_access & !LANDLOCK_ACCESS_FS_EXECUTE,
    );

    // Dev (read + write for /dev/null etc.)
    add_path_rule(
        &ruleset_fd,
        "/dev",
        (read_access & !LANDLOCK_ACCESS_FS_EXECUTE) | LANDLOCK_ACCESS_FS_WRITE_FILE,
    );

    landlock_restrict_self(&ruleset_fd).map_err(LockdownError::Landlock)
}

/// Add a path rule to the Landlock ruleset.
///
/// Errors are logged but not propagated - the path simply won't be
/// accessible in the sandbox. Missing paths (like /nix/store on non-NixOS)
/// should not prevent sandbox creation.
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

// Securebits constants (from <linux/securebits.h>)
const SECBIT_NOROOT: u64 = 1 << 0;
const SECBIT_NOROOT_LOCKED: u64 = 1 << 1;
const SECBIT_NO_SETUID_FIXUP: u64 = 1 << 2;
const SECBIT_NO_SETUID_FIXUP_LOCKED: u64 = 1 << 3;
const SECBIT_KEEP_CAPS_LOCKED: u64 = 1 << 5;
const SECBIT_NO_CAP_AMBIENT_RAISE: u64 = 1 << 6;
const SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED: u64 = 1 << 7;

/// Apply securebits to lock capability state permanently.
///
/// This prevents the process from ever regaining capabilities through
/// any mechanism (exec of setuid, ambient capabilities, etc.).
fn apply_securebits() -> Result<(), LockdownError> {
    let bits = SECBIT_NOROOT
        | SECBIT_NOROOT_LOCKED
        | SECBIT_NO_SETUID_FIXUP
        | SECBIT_NO_SETUID_FIXUP_LOCKED
        | SECBIT_KEEP_CAPS_LOCKED
        | SECBIT_NO_CAP_AMBIENT_RAISE
        | SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED;

    let ret = unsafe { libc::prctl(libc::PR_SET_SECUREBITS, bits, 0, 0, 0) };
    if ret != 0 {
        // Not fatal — securebits may require capabilities we don't have.
        // The important thing is NO_NEW_PRIVS + dropping all caps.
        eprintln!("warning: PR_SET_SECUREBITS failed: {}", last_errno());
    }
    Ok(())
}

/// Set `PR_SET_NO_NEW_PRIVS` — required before `landlock_restrict_self` and seccomp.
fn set_no_new_privs() -> Result<(), LockdownError> {
    let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if ret != 0 {
        Err(LockdownError::Capability(last_errno()))
    } else {
        Ok(())
    }
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
    Ok(())
}

/// Close all file descriptors > 2 using `close_range` syscall.
///
/// This is called separately from lockdown because it must happen after
/// seccomp filter installation and listener fd transfer.
pub fn close_extra_fds() {
    // close_range(3, MAX, 0) — close all fds from 3 to MAX
    unsafe {
        libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0u32);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_path_valid() {
        assert!(open_path("/tmp").is_ok());
    }
}
