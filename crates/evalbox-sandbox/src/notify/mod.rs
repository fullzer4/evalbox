//! Seccomp user notification support.
//!
//! This module provides the supervisor side of seccomp user notification,
//! enabling syscall interception without Linux user namespaces.
//!
//! ## Modules
//!
//! - **supervisor** - Main notification loop that handles intercepted syscalls
//! - **`virtual_fs`** - Path translation for filesystem virtualization
//! - **`scm_rights`** - Unix socket fd passing (child → parent listener fd transfer)

pub mod scm_rights;
pub mod supervisor;
pub mod virtual_fs;

pub use supervisor::{NotifyEvent, Supervisor};
pub use virtual_fs::VirtualFs;
