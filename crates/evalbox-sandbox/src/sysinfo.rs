//! System information and path detection.
//!
//! Detects the system type (NixOS, traditional FHS, etc.) and provides
//! appropriate paths for sandbox configuration.

use std::path::{Path, PathBuf};
use std::sync::LazyLock;

pub static SYSTEM_PATHS: LazyLock<SystemPaths> = LazyLock::new(SystemPaths::detect);

/// System type detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemType {
    /// NixOS - binaries in /nix/store, no standard FHS paths
    NixOS,
    /// Guix - similar to NixOS, binaries in /gnu/store
    Guix,
    /// Standard FHS Linux (Debian, Ubuntu, Fedora, Arch, etc.)
    Fhs,
}

impl SystemType {
    /// Detect the current system type.
    pub fn detect() -> Self {
        // NixOS: Check for definitive markers
        // - /etc/NIXOS is a NixOS-specific file
        // - /nix/store exists and /bin/sh (if it exists) is a symlink to /nix/store
        if Path::new("/etc/NIXOS").exists() {
            return SystemType::NixOS;
        }
        if Path::new("/nix/store").exists() {
            // Check if /bin/sh points to nix store (common on NixOS with compatibility)
            if let Ok(target) = std::fs::read_link("/bin/sh") {
                if target.to_string_lossy().contains("/nix/store") {
                    return SystemType::NixOS;
                }
            }
            // No /bin/sh or not a symlink = pure NixOS
            if !Path::new("/bin/sh").exists() {
                return SystemType::NixOS;
            }
        }

        // Guix: Similar logic
        if Path::new("/gnu/store").exists() {
            if let Ok(target) = std::fs::read_link("/bin/sh") {
                if target.to_string_lossy().contains("/gnu/store") {
                    return SystemType::Guix;
                }
            }
            if !Path::new("/bin/sh").exists() {
                return SystemType::Guix;
            }
        }

        SystemType::Fhs
    }

    pub fn is_nix_like(self) -> bool {
        matches!(self, SystemType::NixOS | SystemType::Guix)
    }
}

/// Paths that exist on the current system for mounting.
#[derive(Debug, Clone)]
pub struct SystemPaths {
    /// System type
    pub system_type: SystemType,
    /// Paths to mount read-only (system directories)
    pub readonly_mounts: Vec<PathBuf>,
    /// Default PATH environment variable
    pub default_path: String,
}

impl SystemPaths {
    /// Detect system paths.
    pub fn detect() -> Self {
        let system_type = SystemType::detect();

        match system_type {
            SystemType::NixOS => Self::nixos_paths(),
            SystemType::Guix => Self::guix_paths(),
            SystemType::Fhs => Self::fhs_paths(),
        }
    }

    fn nixos_paths() -> Self {
        let mut readonly_mounts = Vec::new();

        // On NixOS, we need /nix/store for all binaries and libraries
        if Path::new("/nix/store").exists() {
            readonly_mounts.push(PathBuf::from("/nix/store"));
        }

        // /run/current-system/sw contains symlinks to installed packages
        if Path::new("/run/current-system/sw").exists() {
            readonly_mounts.push(PathBuf::from("/run/current-system/sw"));
        }

        // NOTE: We do NOT mount /etc from host to prevent information leakage.
        // Essential /etc files are created in workspace::setup_minimal_etc()

        // Build PATH from NixOS locations
        let path_dirs = [
            "/run/current-system/sw/bin",
            "/nix/var/nix/profiles/default/bin",
        ];

        let default_path = path_dirs
            .iter()
            .filter(|p| Path::new(p).exists())
            .copied()
            .collect::<Vec<_>>()
            .join(":");

        Self {
            system_type: SystemType::NixOS,
            readonly_mounts,
            default_path: if default_path.is_empty() {
                "/bin".to_string()
            } else {
                default_path
            },
        }
    }

    fn guix_paths() -> Self {
        let mut readonly_mounts = Vec::new();

        if Path::new("/gnu/store").exists() {
            readonly_mounts.push(PathBuf::from("/gnu/store"));
        }

        // NOTE: We do NOT mount /etc from host to prevent information leakage.
        // Essential /etc files are created in workspace::setup_minimal_etc()

        Self {
            system_type: SystemType::Guix,
            readonly_mounts,
            default_path: "/run/current-system/profile/bin".to_string(),
        }
    }

    fn fhs_paths() -> Self {
        // NOTE: /etc is NOT included to prevent information leakage.
        // Essential /etc files are created in workspace::setup_minimal_etc()
        const FHS_DIRS: &[&str] = &["/usr", "/bin", "/lib", "/lib64", "/sbin"];

        let readonly_mounts = FHS_DIRS
            .iter()
            .map(Path::new)
            .filter(|p| p.exists())
            .map(Path::to_path_buf)
            .collect();

        Self {
            system_type: SystemType::Fhs,
            readonly_mounts,
            default_path: "/usr/local/bin:/usr/bin:/bin".to_string(),
        }
    }

    /// Get paths suitable for Landlock rules.
    pub fn landlock_readonly_paths(&self) -> Vec<&Path> {
        self.readonly_mounts.iter().map(|p| p.as_path()).collect()
    }
}

pub fn is_nix_store_path(path: &Path) -> bool {
    path.starts_with("/nix/store")
}

pub fn is_guix_store_path(path: &Path) -> bool {
    path.starts_with("/gnu/store")
}

/// Get the store path for a binary (first component after /nix/store/ or /gnu/store/).
pub fn get_store_path(path: &Path) -> Option<PathBuf> {
    let path_str = path.to_string_lossy();

    for store in ["/nix/store", "/gnu/store"] {
        if path_str.starts_with(store) {
            // Return the entire store since we can't easily know which packages are needed
            return Some(PathBuf::from(store));
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_system_type_detect() {
        let system_type = SystemType::detect();
        // Should detect something
        assert!(matches!(
            system_type,
            SystemType::NixOS | SystemType::Guix | SystemType::Fhs
        ));
    }

    #[test]
    fn test_system_paths_detect() {
        let paths = SystemPaths::detect();
        // Should have a non-empty PATH
        assert!(!paths.default_path.is_empty());
    }

    #[test]
    fn test_is_nix_store_path() {
        assert!(is_nix_store_path(Path::new("/nix/store/abc123/bin/python")));
        assert!(!is_nix_store_path(Path::new("/usr/bin/python")));
    }

    #[test]
    fn test_get_store_path() {
        let nix_path = Path::new("/nix/store/abc123/bin/python");
        assert_eq!(get_store_path(nix_path), Some(PathBuf::from("/nix/store")));

        let usr_path = Path::new("/usr/bin/python");
        assert_eq!(get_store_path(usr_path), None);
    }
}
