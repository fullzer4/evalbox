//! Low-level Linux syscall wrappers for sandboxing.
//!
//! This crate provides thin wrappers around Linux-specific security syscalls
//! that are not available in rustix or libc. For standard syscalls, use rustix.
//!
//! ## Modules
//!
//! - **landlock** - Landlock LSM for filesystem/network/scope access control (kernel 5.13+)
//! - **seccomp** - Seccomp-BPF syscall filtering
//! - **`seccomp_notify`** - Seccomp user notification (`SECCOMP_RET_USER_NOTIF`)
//! - **check** - Runtime system capability detection
//!
//! ## Landlock
//!
//! Landlock provides fine-grained filesystem access control. ABI versions:
//! - ABI 1: Basic filesystem access (kernel 5.13)
//! - ABI 2: File truncation (kernel 5.19)
//! - ABI 3: File permission changes (kernel 6.2)
//! - ABI 4: Network TCP access control (kernel 6.7)
//! - ABI 5: Scoped signals and abstract unix sockets (kernel 6.12)
//!
//! ## Seccomp-BPF
//!
//! Seccomp-BPF allows filtering syscalls via BPF programs. This crate provides
//! a whitelist-based filter that allows ~40 safe syscalls and kills the process
//! on any other syscall.
//!
//! ## Seccomp User Notify
//!
//! Seccomp user notification allows a supervisor process to intercept syscalls
//! from a sandboxed child, enabling filesystem virtualization without namespaces.
//!
//! # Safety
//!
//! This crate contains raw syscall wrappers. Casts between integer types
//! are unavoidable when interfacing with the kernel ABI.

#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]

pub mod check;
pub mod landlock;
pub mod seccomp;
pub mod seccomp_notify;

pub use check::{CheckError, SystemInfo, check};

#[inline]
pub fn last_errno() -> rustix::io::Errno {
    // SAFETY: __errno_location always returns valid thread-local pointer.
    rustix::io::Errno::from_raw_os_error(unsafe { *libc::__errno_location() })
}
