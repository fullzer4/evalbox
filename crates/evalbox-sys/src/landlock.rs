//! Landlock LSM for unprivileged filesystem and network access control.
//!
//! Landlock is a Linux Security Module (LSM) that allows unprivileged processes
//! to restrict their own access to the filesystem and network. Unlike traditional
//! DAC/MAC, Landlock can be used without root privileges.
//!
//! ## ABI Versions
//!
//! | ABI | Kernel | Features |
//! |-----|--------|----------|
//! | 1 | 5.13 | Basic filesystem access |
//! | 2 | 5.19 | `REFER` (cross-directory rename/link) |
//! | 3 | 6.2 | `TRUNCATE` (file truncation) |
//! | 4 | 6.7 | `IOCTL_DEV`, TCP network access |
//! | 5 | 6.12 | `SCOPE_SIGNAL`, `SCOPE_ABSTRACT_UNIX_SOCKET` |
//!
//! ## Usage
//!
//! ```ignore
//! let attr = LandlockRulesetAttr {
//!     handled_access_fs: fs_access_for_abi(abi),
//!     handled_access_net: net_access_for_abi(abi),
//! };
//! let ruleset_fd = landlock_create_ruleset(&attr)?;
//!
//! // Add rules for allowed paths
//! let rule = LandlockPathBeneathAttr { allowed_access, parent_fd };
//! landlock_add_rule_path(&ruleset_fd, &rule)?;
//!
//! // Restrict self - no going back after this!
//! landlock_restrict_self(&ruleset_fd)?;
//! ```
//!
//! ## Important
//!
//! - Once `landlock_restrict_self` is called, it cannot be undone
//! - Access not explicitly allowed is denied
//! - Network blocking requires ABI 4+ (kernel 6.7+)

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use rustix::io::Errno;

use crate::last_errno;

const SYS_LANDLOCK_CREATE_RULESET: i64 = 444;
const SYS_LANDLOCK_ADD_RULE: i64 = 445;
const SYS_LANDLOCK_RESTRICT_SELF: i64 = 446;

const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1 << 0;
const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;

// ABI v1
pub const LANDLOCK_ACCESS_FS_EXECUTE: u64 = 1 << 0;
pub const LANDLOCK_ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
pub const LANDLOCK_ACCESS_FS_READ_FILE: u64 = 1 << 2;
pub const LANDLOCK_ACCESS_FS_READ_DIR: u64 = 1 << 3;
pub const LANDLOCK_ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
pub const LANDLOCK_ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
pub const LANDLOCK_ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
pub const LANDLOCK_ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
pub const LANDLOCK_ACCESS_FS_MAKE_REG: u64 = 1 << 8;
pub const LANDLOCK_ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
pub const LANDLOCK_ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;
pub const LANDLOCK_ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
pub const LANDLOCK_ACCESS_FS_MAKE_SYM: u64 = 1 << 12;

// ABI v2
pub const LANDLOCK_ACCESS_FS_REFER: u64 = 1 << 13;

// ABI v3
pub const LANDLOCK_ACCESS_FS_TRUNCATE: u64 = 1 << 14;

// ABI v4
pub const LANDLOCK_ACCESS_FS_IOCTL_DEV: u64 = 1 << 15;
pub const LANDLOCK_ACCESS_NET_BIND_TCP: u64 = 1 << 0;
pub const LANDLOCK_ACCESS_NET_CONNECT_TCP: u64 = 1 << 1;

// ABI v5 - Scoped restrictions
/// Block abstract unix socket connections outside the sandbox.
pub const LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET: u64 = 1 << 0;
/// Block signals to processes outside the sandbox.
pub const LANDLOCK_SCOPE_SIGNAL: u64 = 1 << 1;

#[repr(C)]
#[derive(Debug, Default)]
pub struct LandlockRulesetAttr {
    pub handled_access_fs: u64,
    pub handled_access_net: u64,
    /// ABI 5+: Scoped restrictions (signal and abstract unix socket isolation).
    pub scoped: u64,
}

#[repr(C)]
#[derive(Debug)]
pub struct LandlockPathBeneathAttr {
    pub allowed_access: u64,
    pub parent_fd: RawFd,
}

/// Returns the Landlock ABI version supported by the kernel.
///
/// # Errors
///
/// Returns `Errno` if the kernel doesn't support Landlock.
pub fn landlock_abi_version() -> Result<u32, Errno> {
    // SAFETY: Passing null with size 0 and VERSION flag queries the ABI version.
    let ret = unsafe {
        libc::syscall(
            SYS_LANDLOCK_CREATE_RULESET,
            std::ptr::null::<LandlockRulesetAttr>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if ret < 0 {
        Err(last_errno())
    } else {
        Ok(ret as u32)
    }
}

/// Creates a new Landlock ruleset.
///
/// # Errors
///
/// Returns `Errno` if the ruleset creation fails.
pub fn landlock_create_ruleset(attr: &LandlockRulesetAttr) -> Result<OwnedFd, Errno> {
    // SAFETY: attr points to valid memory with correct size.
    let ret = unsafe {
        libc::syscall(
            SYS_LANDLOCK_CREATE_RULESET,
            attr as *const LandlockRulesetAttr,
            size_of::<LandlockRulesetAttr>(),
            0u32,
        )
    };
    if ret < 0 {
        Err(last_errno())
    } else {
        // SAFETY: On success, ret is a valid owned file descriptor.
        Ok(unsafe { OwnedFd::from_raw_fd(ret as RawFd) })
    }
}

/// Adds a path-based rule to a Landlock ruleset.
///
/// # Errors
///
/// Returns `Errno` if adding the rule fails.
pub fn landlock_add_rule_path(
    ruleset_fd: &OwnedFd,
    attr: &LandlockPathBeneathAttr,
) -> Result<(), Errno> {
    // SAFETY: ruleset_fd is valid, attr points to valid memory.
    let ret = unsafe {
        libc::syscall(
            SYS_LANDLOCK_ADD_RULE,
            ruleset_fd.as_raw_fd(),
            LANDLOCK_RULE_PATH_BENEATH,
            attr as *const LandlockPathBeneathAttr,
            0u32,
        )
    };
    if ret < 0 { Err(last_errno()) } else { Ok(()) }
}

/// Restricts the calling thread to the given Landlock ruleset.
///
/// # Errors
///
/// Returns `Errno` if the restriction fails.
pub fn landlock_restrict_self(ruleset_fd: &OwnedFd) -> Result<(), Errno> {
    // SAFETY: ruleset_fd is a valid file descriptor.
    let ret = unsafe { libc::syscall(SYS_LANDLOCK_RESTRICT_SELF, ruleset_fd.as_raw_fd(), 0u32) };
    if ret < 0 { Err(last_errno()) } else { Ok(()) }
}

/// Returns the filesystem access flags for the given ABI version.
pub fn fs_access_for_abi(abi: u32) -> u64 {
    let mut access = LANDLOCK_ACCESS_FS_EXECUTE
        | LANDLOCK_ACCESS_FS_WRITE_FILE
        | LANDLOCK_ACCESS_FS_READ_FILE
        | LANDLOCK_ACCESS_FS_READ_DIR
        | LANDLOCK_ACCESS_FS_REMOVE_DIR
        | LANDLOCK_ACCESS_FS_REMOVE_FILE
        | LANDLOCK_ACCESS_FS_MAKE_CHAR
        | LANDLOCK_ACCESS_FS_MAKE_DIR
        | LANDLOCK_ACCESS_FS_MAKE_REG
        | LANDLOCK_ACCESS_FS_MAKE_SOCK
        | LANDLOCK_ACCESS_FS_MAKE_FIFO
        | LANDLOCK_ACCESS_FS_MAKE_BLOCK
        | LANDLOCK_ACCESS_FS_MAKE_SYM;

    if abi >= 2 {
        access |= LANDLOCK_ACCESS_FS_REFER;
    }
    if abi >= 3 {
        access |= LANDLOCK_ACCESS_FS_TRUNCATE;
    }
    if abi >= 4 {
        access |= LANDLOCK_ACCESS_FS_IOCTL_DEV;
    }

    access
}

/// Returns the network access flags for the given ABI version.
pub fn net_access_for_abi(abi: u32) -> u64 {
    if abi >= 4 {
        LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP
    } else {
        0
    }
}

/// Returns the scoped restriction flags for the given ABI version.
///
/// ABI 5+ supports signal isolation and abstract unix socket isolation,
/// replacing the need for PID and IPC namespaces.
pub fn scope_for_abi(abi: u32) -> u64 {
    if abi >= 5 {
        LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET | LANDLOCK_SCOPE_SIGNAL
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abi_version() {
        if let Ok(v) = landlock_abi_version() {
            assert!(v >= 1);
        }
    }

    #[test]
    fn fs_access_increases_with_abi() {
        assert!(fs_access_for_abi(2) > fs_access_for_abi(1));
        assert!(fs_access_for_abi(3) > fs_access_for_abi(2));
        assert!(fs_access_for_abi(4) > fs_access_for_abi(3));
    }
}
