//! User namespace and ID mapping setup.
//!
//! Sets up UID/GID mappings so the sandboxed process runs as root (UID 0)
//! inside the namespace, but maps to the real user outside.
//!
//! ## How It Works
//!
//! ```text
//! Outside namespace:  uid=1000 (real user)
//!                          │
//!                    ┌─────▼─────┐
//!                    │  uid_map  │  "0 1000 1"
//!                    └─────┬─────┘
//!                          │
//! Inside namespace:   uid=0 (appears as root)
//! ```
//!
//! ## Security
//!
//! - `deny_setgroups` must be called BEFORE writing `gid_map` (kernel requirement)
//! - The process appears as root inside but has no real privileges
//! - This enables pivot_root and mount operations inside the namespace

use std::fs;
use std::io;

/// Write UID mapping for a process in a user namespace.
///
/// Maps `inside_uid` (seen inside namespace) to `outside_uid` (real UID).
/// The "1" at the end means we map exactly one UID.
pub fn write_uid_map(pid: libc::pid_t, inside_uid: u32, outside_uid: u32) -> io::Result<()> {
    fs::write(
        format!("/proc/{pid}/uid_map"),
        format!("{inside_uid} {outside_uid} 1\n"),
    )
}

/// Write GID mapping for a process in a user namespace.
///
/// Maps `inside_gid` (seen inside namespace) to `outside_gid` (real GID).
pub fn write_gid_map(pid: libc::pid_t, inside_gid: u32, outside_gid: u32) -> io::Result<()> {
    fs::write(
        format!("/proc/{pid}/gid_map"),
        format!("{inside_gid} {outside_gid} 1\n"),
    )
}

/// Deny setgroups syscall for a process.
///
/// # Safety Order
///
/// MUST be called before `write_gid_map`. The kernel requires this to prevent
/// privilege escalation via group manipulation.
pub fn deny_setgroups(pid: libc::pid_t) -> io::Result<()> {
    fs::write(format!("/proc/{pid}/setgroups"), "deny\n")
}

/// Set up complete ID mappings for a child process.
///
/// Maps UID 0 and GID 0 inside the namespace to the current user's
/// real UID/GID outside. This allows the sandboxed process to appear
/// as root while having no actual privileges.
pub fn setup_id_maps(child_pid: libc::pid_t) -> io::Result<()> {
    // SAFETY: getuid/getgid are always safe to call
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };

    // SAFETY: deny_setgroups MUST come before write_gid_map
    deny_setgroups(child_pid)?;
    write_uid_map(child_pid, 0, uid)?;
    write_gid_map(child_pid, 0, gid)
}

#[cfg(test)]
mod tests {
    #[test]
    fn current_uid_gid() {
        // SAFETY: getuid/getgid are always safe
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };
        assert!(uid > 0 || gid > 0);
    }
}
