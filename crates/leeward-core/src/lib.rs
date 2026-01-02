//! # leeward-core
//!
//! Linux process isolation primitives for secure code execution.
//!
//! This crate provides the core isolation mechanisms:
//! - Linux namespaces via clone3 (user, pid, mount, net, ipc)
//! - seccomp user notifications (SECCOMP_USER_NOTIF)
//! - Landlock filesystem restrictions
//! - cgroups v2 resource limits (CLONE_INTO_CGROUP)
//! - Shared memory for zero-copy results (memfd + mmap)
//! - Pipe-based code delivery to pre-forked workers

#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]

pub mod config;
pub mod error;
pub mod isolation;
pub mod pipe;
pub mod protocol;
pub mod result;
pub mod shm;
pub mod worker;

pub use config::SandboxConfig;
pub use error::LeewardError;
pub use result::ExecutionResult;

/// Crate-level result type
pub type Result<T> = std::result::Result<T, LeewardError>;
