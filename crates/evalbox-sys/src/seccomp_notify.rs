//! Seccomp user notification (`SECCOMP_RET_USER_NOTIF`) support.
//!
//! Seccomp user notification allows a supervisor process to intercept
//! syscalls from a sandboxed child and make decisions on its behalf.
//! This enables filesystem virtualization without user namespaces.
//!
//! ## Architecture
//!
//! 1. Child installs a seccomp filter with `SECCOMP_FILTER_FLAG_NEW_LISTENER`
//! 2. This returns a "listener fd" which is passed to the parent via `SCM_RIGHTS`
//! 3. Parent polls the listener fd; when readable, calls `SECCOMP_IOCTL_NOTIF_RECV`
//! 4. Parent inspects the syscall and either:
//!    - Returns `SECCOMP_USER_NOTIF_FLAG_CONTINUE` to let it proceed
//!    - Returns an error code to deny it
//!    - Uses `SECCOMP_IOCTL_NOTIF_ADDFD` to inject a file descriptor
//!
//! ## TOCTOU Protection
//!
//! Between receiving a notification and responding, the child's memory may change.
//! Always call `SECCOMP_IOCTL_NOTIF_ID_VALID` after reading child memory to verify
//! the notification is still valid.

use std::os::fd::{FromRawFd, OwnedFd};

use rustix::io::Errno;

use crate::last_errno;
use crate::seccomp::SockFprog;

// Seccomp constants for notify
const SECCOMP_SET_MODE_FILTER: u32 = 1;
pub const SECCOMP_FILTER_FLAG_NEW_LISTENER: u32 = 1 << 3;

/// Let the syscall proceed as-is (supervisor approves).
pub const SECCOMP_USER_NOTIF_FLAG_CONTINUE: u32 = 1;

/// Atomically inject fd and respond to the notification.
pub const SECCOMP_ADDFD_FLAG_SEND: u32 = 1 << 0;
/// Replace an existing fd in the target process.
pub const SECCOMP_ADDFD_FLAG_SETFD: u32 = 1 << 1;

// ioctl numbers for seccomp notify (from kernel headers)
// These are architecture-dependent; values below are for x86_64.
// SECCOMP_IOCTL_NOTIF_RECV = SECCOMP_IOWR(0, struct seccomp_notif)
// SECCOMP_IOCTL_NOTIF_SEND = SECCOMP_IOWR(1, struct seccomp_notif_resp)
// SECCOMP_IOCTL_NOTIF_ID_VALID = SECCOMP_IOW(2, __u64)
// SECCOMP_IOCTL_NOTIF_ADDFD = SECCOMP_IOW(3, struct seccomp_notif_addfd)

/// ioctl to receive a notification from the seccomp listener fd.
pub const SECCOMP_IOCTL_NOTIF_RECV: u64 = 0xc0502100;
/// ioctl to send a response to a seccomp notification.
pub const SECCOMP_IOCTL_NOTIF_SEND: u64 = 0xc0182101;
/// ioctl to check if a notification ID is still valid (TOCTOU protection).
pub const SECCOMP_IOCTL_NOTIF_ID_VALID: u64 = 0x40082102;
/// ioctl to inject a file descriptor into the notifying process.
pub const SECCOMP_IOCTL_NOTIF_ADDFD: u64 = 0x40182103;

/// Seccomp notification data (mirrors kernel `struct seccomp_data`).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SeccompData {
    /// Syscall number.
    pub nr: i32,
    /// Architecture (`AUDIT_ARCH_*`).
    pub arch: u32,
    /// Instruction pointer at time of syscall.
    pub instruction_pointer: u64,
    /// Syscall arguments.
    pub args: [u64; 6],
}

/// Seccomp notification received from the child (mirrors kernel `struct seccomp_notif`).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SeccompNotif {
    /// Unique notification ID.
    pub id: u64,
    /// PID of the notifying process (in supervisor's PID namespace).
    pub pid: u32,
    /// Flags (currently unused, must be 0).
    pub flags: u32,
    /// The syscall data.
    pub data: SeccompData,
}

impl Default for SeccompNotif {
    fn default() -> Self {
        // SAFETY: SeccompNotif is a plain C struct with no invariants.
        unsafe { std::mem::zeroed() }
    }
}

/// Response to a seccomp notification (mirrors kernel `struct seccomp_notif_resp`).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SeccompNotifResp {
    /// Must match the notification ID.
    pub id: u64,
    /// Return value for the syscall.
    pub val: i64,
    /// Errno value (negated in kernel).
    pub error: i32,
    /// Flags (e.g., `SECCOMP_USER_NOTIF_FLAG_CONTINUE`).
    pub flags: u32,
}

/// Inject a file descriptor into the notifying process
/// (mirrors kernel `struct seccomp_notif_addfd`).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SeccompNotifAddfd {
    /// Must match the notification ID.
    pub id: u64,
    /// Flags (e.g., `SECCOMP_ADDFD_FLAG_SEND`).
    pub flags: u32,
    /// The fd in the supervisor to inject.
    pub srcfd: u32,
    /// The fd number to use in the target (0 = kernel picks).
    pub newfd: u32,
    /// Flags for the new fd (e.g., `O_CLOEXEC`).
    pub newfd_flags: u32,
}

/// Install a seccomp filter with `SECCOMP_FILTER_FLAG_NEW_LISTENER`.
///
/// Returns the listener fd which can be used to receive notifications.
/// The caller must have already called `PR_SET_NO_NEW_PRIVS`.
///
/// # Safety
///
/// The filter must be a valid BPF program. This permanently restricts
/// syscalls for this thread.
///
/// # Errors
///
/// Returns `Errno` if the filter cannot be installed.
pub unsafe fn seccomp_set_mode_filter_listener(fprog: &SockFprog) -> Result<OwnedFd, Errno> {
    unsafe {
        let ret = libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        if ret != 0 {
            return Err(last_errno());
        }

        let ret = libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER,
            SECCOMP_FILTER_FLAG_NEW_LISTENER,
            fprog as *const _,
        );
        if ret < 0 {
            Err(last_errno())
        } else {
            // SAFETY: On success, ret is a valid listener file descriptor.
            Ok(OwnedFd::from_raw_fd(ret as i32))
        }
    }
}

/// Receive a notification from the seccomp listener fd.
///
/// Blocks until a notification is available (or use poll/epoll first).
///
/// # Errors
///
/// Returns `Errno` on failure (e.g., `ENOENT` if the target died).
pub fn notif_recv(listener_fd: i32, notif: &mut SeccompNotif) -> Result<(), Errno> {
    let ret = unsafe {
        libc::ioctl(
            listener_fd,
            SECCOMP_IOCTL_NOTIF_RECV,
            notif as *mut SeccompNotif,
        )
    };
    if ret < 0 { Err(last_errno()) } else { Ok(()) }
}

/// Send a response to a seccomp notification.
///
/// # Errors
///
/// Returns `Errno` on failure.
pub fn notif_send(listener_fd: i32, resp: &SeccompNotifResp) -> Result<(), Errno> {
    let ret = unsafe {
        libc::ioctl(
            listener_fd,
            SECCOMP_IOCTL_NOTIF_SEND,
            resp as *const SeccompNotifResp,
        )
    };
    if ret < 0 { Err(last_errno()) } else { Ok(()) }
}

/// Check if a notification ID is still valid.
///
/// Must be called after reading from child's `/proc/pid/mem` to protect
/// against TOCTOU attacks.
///
/// # Errors
///
/// Returns `Errno::NOENT` if the notification is no longer valid.
pub fn notif_id_valid(listener_fd: i32, id: u64) -> Result<(), Errno> {
    let ret = unsafe { libc::ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_ID_VALID, &id as *const u64) };
    if ret < 0 { Err(last_errno()) } else { Ok(()) }
}

/// Inject a file descriptor into the notifying process.
///
/// With `SECCOMP_ADDFD_FLAG_SEND`, this atomically injects the fd and
/// responds to the notification (the return value becomes the new fd number
/// in the target process).
///
/// # Errors
///
/// Returns `Errno` on failure.
pub fn notif_addfd(listener_fd: i32, addfd: &SeccompNotifAddfd) -> Result<i32, Errno> {
    let ret = unsafe {
        libc::ioctl(
            listener_fd,
            SECCOMP_IOCTL_NOTIF_ADDFD,
            addfd as *const SeccompNotifAddfd,
        )
    };
    if ret < 0 { Err(last_errno()) } else { Ok(ret) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn struct_sizes() {
        // Verify struct sizes match kernel expectations
        assert_eq!(size_of::<SeccompData>(), 64);
        assert_eq!(size_of::<SeccompNotif>(), 80);
        assert_eq!(size_of::<SeccompNotifResp>(), 24);
        assert_eq!(size_of::<SeccompNotifAddfd>(), 24);
    }

    #[test]
    fn default_notif_is_zeroed() {
        let notif = SeccompNotif::default();
        assert_eq!(notif.id, 0);
        assert_eq!(notif.pid, 0);
        assert_eq!(notif.data.nr, 0);
    }
}
