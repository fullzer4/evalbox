//! # leeward-core
//!
//! Linux process isolation primitives for secure code execution.
//!
//! This crate provides the core isolation mechanisms:
//! - Linux namespaces (user, pid, mount, net, ipc)
//! - seccomp-bpf syscall filtering
//! - Landlock filesystem restrictions  
//! - cgroups v2 resource limits

#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]

pub mod config;
pub mod error;
pub mod isolation;
pub mod result;
pub mod worker;

pub use config::SandboxConfig;
pub use error::LeewardError;
pub use result::ExecutionResult;

/// Crate-level result type
pub type Result<T> = std::result::Result<T, LeewardError>;
