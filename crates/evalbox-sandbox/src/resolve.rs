//! Binary path resolution and mount detection.

use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::plan::Mount;
use crate::sysinfo::{SYSTEM_PATHS, SystemPaths, SystemType};

#[derive(Debug, Clone)]
pub struct ResolvedBinary {
    pub path: PathBuf,
    pub required_mounts: Vec<Mount>,
}

#[derive(Debug, Error)]
pub enum ResolveError {
    #[error("command not found: {0}")]
    NotFound(String),
}

/// Resolve command to absolute path and detect required mounts.
pub fn resolve_binary(cmd: &str) -> Result<ResolvedBinary, ResolveError> {
    let path = if cmd.starts_with('/') {
        let p = PathBuf::from(cmd);
        if !p.exists() && !cmd.starts_with("/work/") {
            return Err(ResolveError::NotFound(cmd.to_string()));
        }
        p
    } else {
        which::which(cmd).map_err(|_| ResolveError::NotFound(cmd.to_string()))?
    };

    let sys_paths = &*SYSTEM_PATHS;
    let required_mounts = detect_mounts(&path, sys_paths);

    Ok(ResolvedBinary {
        path,
        required_mounts,
    })
}

fn detect_mounts(binary: &Path, sys_paths: &SystemPaths) -> Vec<Mount> {
    let path_str = binary.to_string_lossy();
    let mut mounts = Vec::new();

    for mount_path in &sys_paths.readonly_mounts {
        mounts.push(Mount::ro(mount_path));
    }

    if sys_paths.system_type == SystemType::Fhs {
        if path_str.starts_with("/usr") {
            add_if_missing(&mut mounts, "/usr");
        } else if path_str.starts_with("/bin") || path_str.starts_with("/sbin") {
            if Path::new("/bin").is_symlink() {
                add_if_missing(&mut mounts, "/usr");
            } else {
                add_if_missing(&mut mounts, "/bin");
            }
        }
    }

    mounts
}

fn add_if_missing(mounts: &mut Vec<Mount>, path: &str) {
    let path_buf = PathBuf::from(path);
    if !mounts.iter().any(|m| m.source == path_buf) && path_buf.exists() {
        mounts.push(Mount::ro(path_buf));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_echo() {
        let resolved = resolve_binary("echo").unwrap();
        assert!(resolved.path.exists());
        assert!(resolved.path.is_absolute());
    }

    #[test]
    fn resolve_nonexistent() {
        assert!(resolve_binary("nonexistent_binary_12345").is_err());
    }

    #[test]
    fn detect_nix_mounts() {
        let sys_paths = &*SYSTEM_PATHS;
        let mounts = detect_mounts(Path::new("/nix/store/abc123/bin/echo"), sys_paths);

        if sys_paths.system_type == SystemType::NixOS {
            assert!(mounts.iter().any(|m| m.source == Path::new("/nix/store")));
        }
    }

    #[test]
    fn detect_fhs_mounts() {
        let sys_paths = &*SYSTEM_PATHS;
        let mounts = detect_mounts(Path::new("/usr/bin/echo"), sys_paths);

        // Only check for /usr mount if we're on an actual FHS system with /usr
        if sys_paths.system_type == SystemType::Fhs && Path::new("/usr").exists() {
            assert!(mounts.iter().any(|m| m.source == Path::new("/usr")));
        }
    }

    #[test]
    fn resolve_has_system_mounts() {
        let resolved = resolve_binary("sh").unwrap();
        assert!(!resolved.required_mounts.is_empty());
    }
}
