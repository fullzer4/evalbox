//! Isolation mechanisms for sandboxed processes.
//!
//! This module contains all the security isolation layers:
//!
//! - **namespace** - User namespace and ID mapping setup
//! - **rootfs** - Filesystem setup (bind mounts, pivot_root, rlimits)
//! - **lockdown** - Security restrictions (Landlock, seccomp, capabilities)

mod lockdown;
mod namespace;
mod rootfs;

pub use lockdown::{lockdown, LockdownError};
pub use namespace::setup_id_maps;
pub use rootfs::{
    bind_mount, make_rprivate, mount_minimal_dev, mount_proc, pivot_root_and_cleanup, set_hostname,
};
