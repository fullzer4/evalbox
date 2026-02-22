//! Isolation mechanisms for sandboxed processes.
//!
//! This module contains all the security isolation layers:
//!
//! - **lockdown** - Security restrictions (Landlock v5, seccomp, securebits, capabilities)
//! - **rlimits** - Resource limits (memory, CPU, files, processes)

mod lockdown;
pub mod rlimits;

pub use lockdown::{LockdownError, close_extra_fds, lockdown};
