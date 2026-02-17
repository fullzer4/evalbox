//! System capability checking.
//!
//! Verifies at runtime that the kernel supports all required features for sandboxing.
//! The check is performed once and cached in a static `OnceLock`.
//!
//! ## Required Features
//!
//! | Feature | Minimum | Check Method |
//! |---------|---------|--------------|
//! | Kernel | 5.13 | `uname` syscall |
//! | Landlock | ABI 1 | `landlock_create_ruleset` with VERSION flag |
//! | User NS | enabled | `/proc/sys/kernel/unprivileged_userns_clone` or fork+unshare test |
//! | Seccomp | enabled | `prctl(PR_GET_SECCOMP)` |
//!
//! ## Usage
//!
//! ```ignore
//! match check::check() {
//!     Ok(info) => println!("Landlock ABI: {}", info.landlock_abi),
//!     Err(e) => eprintln!("System not supported: {}", e),
//! }
//! ```
//!
//! ## User Namespaces
//!
//! User namespace support varies by distribution:
//! - **Debian/Ubuntu**: `/proc/sys/kernel/unprivileged_userns_clone`
//! - **NixOS/Fedora**: `/proc/sys/user/max_user_namespaces`
//! - **Fallback**: Fork + unshare test

use std::sync::OnceLock;

use rustix::system::uname;
use thiserror::Error;

use crate::landlock;
use crate::seccomp;

/// Information about the system's sandboxing capabilities.
#[derive(Debug, Clone)]
pub struct SystemInfo {
    pub kernel_version: (u32, u32, u32),
    pub landlock_abi: u32,
    pub user_ns_enabled: bool,
    pub seccomp_enabled: bool,
}

/// Errors that can occur during system capability checking.
#[derive(Debug, Clone, Error)]
pub enum CheckError {
    #[error("kernel version {}.{}.{} is too old, need at least {}.{}.{}", .found.0, .found.1, .found.2, .required.0, .required.1, .required.2)]
    KernelTooOld {
        required: (u32, u32, u32),
        found: (u32, u32, u32),
    },

    #[error("landlock is not available")]
    LandlockNotAvailable,

    #[error("user namespaces are disabled")]
    UserNamespacesDisabled,

    #[error("seccomp is not available")]
    SeccompNotAvailable,

    #[error("failed to read kernel version")]
    KernelVersionReadFailed,
}

// Minimum kernel version: 5.13 (first with Landlock)
const MIN_KERNEL_VERSION: (u32, u32, u32) = (5, 13, 0);

static SYSTEM_INFO: OnceLock<Result<SystemInfo, CheckError>> = OnceLock::new();

/// Check system capabilities and cache the result.
///
/// This function checks all required system capabilities for sandboxing
/// and caches the result. Subsequent calls return the cached result.
pub fn check() -> Result<&'static SystemInfo, &'static CheckError> {
    SYSTEM_INFO.get_or_init(check_impl).as_ref()
}

fn check_impl() -> Result<SystemInfo, CheckError> {
    let kernel_version = get_kernel_version()?;
    if kernel_version < MIN_KERNEL_VERSION {
        return Err(CheckError::KernelTooOld {
            required: MIN_KERNEL_VERSION,
            found: kernel_version,
        });
    }

    let landlock_abi = landlock::landlock_abi_version().unwrap_or(0);
    if landlock_abi == 0 {
        return Err(CheckError::LandlockNotAvailable);
    }

    let user_ns_enabled = check_user_namespaces();
    if !user_ns_enabled {
        return Err(CheckError::UserNamespacesDisabled);
    }

    let seccomp_enabled = seccomp::seccomp_available();
    if !seccomp_enabled {
        return Err(CheckError::SeccompNotAvailable);
    }

    Ok(SystemInfo {
        kernel_version,
        landlock_abi,
        user_ns_enabled,
        seccomp_enabled,
    })
}

fn get_kernel_version() -> Result<(u32, u32, u32), CheckError> {
    let uts = uname();
    let release = uts
        .release()
        .to_str()
        .map_err(|_| CheckError::KernelVersionReadFailed)?;
    parse_kernel_version(release)
}

fn parse_kernel_version(release: &str) -> Result<(u32, u32, u32), CheckError> {
    let parts: Vec<&str> = release.split('.').collect();
    if parts.len() < 2 {
        return Err(CheckError::KernelVersionReadFailed);
    }

    let major = parts[0]
        .parse::<u32>()
        .map_err(|_| CheckError::KernelVersionReadFailed)?;

    let minor = parts[1]
        .parse::<u32>()
        .map_err(|_| CheckError::KernelVersionReadFailed)?;

    // Patch might have additional suffix like "0-generic"
    let patch = parts
        .get(2)
        .and_then(|p| p.split('-').next())
        .and_then(|p| p.parse::<u32>().ok())
        .unwrap_or(0);

    Ok((major, minor, patch))
}

fn check_user_namespaces() -> bool {
    // Check sysctl first (Debian/Ubuntu)
    if let Ok(content) = std::fs::read_to_string("/proc/sys/kernel/unprivileged_userns_clone") {
        return content.trim() == "1";
    }

    // Check max_user_namespaces (NixOS and others)
    if let Ok(content) = std::fs::read_to_string("/proc/sys/user/max_user_namespaces")
        && content.trim().parse::<u32>().unwrap_or(0) > 0
    {
        return true;
    }

    // Last resort: fork + unshare test (must fork to avoid polluting parent)
    // SAFETY: fork/unshare/waitpid are safe when used correctly. Child exits immediately.
    unsafe {
        let pid = libc::fork();
        if pid < 0 {
            return false;
        }
        if pid == 0 {
            let ret = libc::unshare(libc::CLONE_NEWUSER);
            libc::_exit(if ret == 0 { 0 } else { 1 });
        }
        let mut status: i32 = 0;
        libc::waitpid(pid, &mut status, 0);
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_kernel_version() {
        assert_eq!(parse_kernel_version("5.15.0").unwrap(), (5, 15, 0));
        assert_eq!(parse_kernel_version("6.1.0-generic").unwrap(), (6, 1, 0));
        assert_eq!(
            parse_kernel_version("5.4.0-150-generic").unwrap(),
            (5, 4, 0)
        );
    }

    #[test]
    fn test_check() {
        match check() {
            Ok(info) => {
                println!("Kernel version: {:?}", info.kernel_version);
                println!("Landlock ABI: {}", info.landlock_abi);
                println!("User NS enabled: {}", info.user_ns_enabled);
                println!("Seccomp enabled: {}", info.seccomp_enabled);
            }
            Err(e) => {
                println!("System check failed: {e}");
            }
        }
    }
}
