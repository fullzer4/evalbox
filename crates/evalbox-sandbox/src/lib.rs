//! evalbox-sandbox: Sandbox orchestration
//!
//! This crate provides secure sandboxed execution of untrusted code on Linux.
//! It combines multiple isolation mechanisms for defense in depth:
//!
//! - **Landlock v5** - Filesystem, network, signal, and IPC access control
//! - **Seccomp-BPF** - Syscall whitelist (~40 allowed syscalls)
//! - **Seccomp User Notify** - Optional syscall interception for FS virtualization
//! - **Rlimits** - Resource limits (memory, CPU, files, processes)
//! - **Capabilities** - All capabilities dropped, `NO_NEW_PRIVS` enforced
//!
//! No user namespaces required — works inside Docker with default seccomp profile.
//!
//! ## Quick Start
//!
//! ```ignore
//! use evalbox_sandbox::{Executor, Plan};
//!
//! let plan = Plan::new(["echo", "hello"]);
//! let output = Executor::run(plan)?;
//! assert_eq!(output.stdout, b"hello\n");
//! ```
//!
//! ## Requirements
//!
//! - Linux kernel 6.12+ (for Landlock ABI 5)
//! - Seccomp enabled in kernel

#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]

pub mod executor;
pub mod isolation;
pub mod monitor;
pub mod notify;
pub mod plan;
pub mod resolve;
pub mod sysinfo;
pub mod validate;
pub mod workspace;

pub use executor::{Event, Executor, ExecutorError, SandboxId};
pub use monitor::{Output, Status};
pub use plan::{Landlock, Mount, NotifyMode, Plan, Syscalls, UserFile};
pub use resolve::{ResolveError, ResolvedBinary, resolve_binary};
