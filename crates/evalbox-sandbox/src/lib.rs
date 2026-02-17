//! evalbox-sandbox: Sandbox orchestration
//!
//! This crate provides secure sandboxed execution of untrusted code on Linux.
//! It combines multiple isolation mechanisms for defense in depth:
//!
//! - **User namespaces** - Unprivileged containers, UID 0 inside = real user outside
//! - **Mount namespaces** - Private filesystem view with minimal bind mounts
//! - **Pivot root** - Change root directory, unmount host filesystem
//! - **Landlock** - Filesystem and network access control (kernel 5.13+)
//! - **Seccomp-BPF** - Syscall whitelist (~40 allowed syscalls)
//! - **Rlimits** - Resource limits (memory, CPU, files, processes)
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
//! - Linux kernel 5.13+ (for Landlock ABI 1+)
//! - User namespaces enabled (`/proc/sys/kernel/unprivileged_userns_clone = 1`)
//! - Seccomp enabled in kernel

#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]

pub mod executor;
pub mod isolation;
pub mod monitor;
pub mod plan;
pub mod resolve;
pub mod sysinfo;
pub mod validate;
pub mod workspace;

pub use executor::{Event, Executor, ExecutorError, SandboxId};
pub use monitor::{Output, Status};
pub use plan::{Landlock, Mount, Plan, Syscalls, UserFile};
pub use resolve::{ResolveError, ResolvedBinary, resolve_binary};

// Backwards compatibility
#[allow(deprecated)]
#[doc(hidden)]
pub use plan::SandboxPlan;
