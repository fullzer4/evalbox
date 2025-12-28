//! Linux isolation primitives
//!
//! This module contains the core isolation mechanisms:
//! - `namespace` - Linux namespaces (user, pid, mount, net, ipc)
//! - `seccomp` - syscall filtering with seccomp-bpf
//! - `landlock` - filesystem access control
//! - `cgroups` - resource limits
//! - `mounts` - filesystem setup with bind mounts and tmpfs

pub mod cgroups;
pub mod landlock;
pub mod mounts;
pub mod namespace;
pub mod seccomp;

pub use self::cgroups::CgroupsConfig;
pub use self::landlock::LandlockConfig;
pub use self::mounts::MountConfig;
pub use self::namespace::NamespaceConfig;
pub use self::seccomp::SeccompConfig;
