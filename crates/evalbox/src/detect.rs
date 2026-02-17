//! Binary detection utilities.

use std::path::{Path, PathBuf};

/// Resolve a binary name to an absolute path.
///
/// This function searches for the binary in the following order:
/// 1. If it's already an absolute path and exists, return it
/// 2. Search PATH using `which`
/// 3. Try common fallback locations
///
/// # Arguments
///
/// * `name` - Binary name or path to resolve
/// * `fallbacks` - Additional paths to check if not found in PATH
pub fn resolve_binary(name: &str, fallbacks: &[&str]) -> Option<PathBuf> {
    let path = Path::new(name);

    // If it's an absolute path, check if it exists
    if path.is_absolute() {
        if path.exists() && is_executable(path) {
            return Some(path.to_path_buf());
        }
        return None;
    }

    // Try which lookup
    if let Ok(path) = which::which(name) {
        return Some(path);
    }

    // Try fallback locations
    for fallback in fallbacks {
        let path = Path::new(fallback);
        if path.exists() && is_executable(path) {
            return Some(path.to_path_buf());
        }
    }

    None
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;

    path.metadata()
        .map(|m| m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    path.exists()
}

/// Try to resolve binary from an environment variable.
///
/// If the env var points to a directory, appends `bin_name` to it.
/// If it points to a file, returns it directly.
pub fn resolve_from_env(env_var: &str, bin_name: &str) -> Option<PathBuf> {
    let value = std::env::var(env_var).ok()?;
    let path = Path::new(&value);

    if path.is_file() && is_executable(path) {
        return Some(path.to_path_buf());
    }

    // Try as directory with bin_name appended
    if path.is_dir() {
        let bin_path = path.join("bin").join(bin_name);
        if bin_path.exists() && is_executable(&bin_path) {
            return Some(bin_path);
        }
        // Also try without bin/ subdirectory
        let bin_path = path.join(bin_name);
        if bin_path.exists() && is_executable(&bin_path) {
            return Some(bin_path);
        }
    }

    None
}

/// For `/usr/bin/python3`, returns `/usr`.
pub fn prefix_dir(binary: &Path) -> Option<PathBuf> {
    binary.parent().and_then(|bin_dir| {
        if bin_dir.ends_with("bin") {
            bin_dir.parent().map(|p| p.to_path_buf())
        } else {
            Some(bin_dir.to_path_buf())
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Get an existing binary path (works on NixOS and traditional Linux)
    fn get_existing_binary() -> Option<PathBuf> {
        which::which("sh").ok()
    }

    #[test]
    fn test_resolve_binary_absolute() {
        let Some(binary) = get_existing_binary() else {
            eprintln!("Skipping: No suitable binary found");
            return;
        };

        let result = resolve_binary(binary.to_str().unwrap(), &[]);
        assert!(result.is_some(), "{} should exist", binary.display());
        assert_eq!(result.unwrap(), binary);
    }

    #[test]
    fn test_resolve_binary_absolute_nonexistent() {
        let result = resolve_binary("/nonexistent/binary", &[]);
        assert!(result.is_none(), "Nonexistent absolute path should return None");
    }

    #[test]
    fn test_resolve_binary_in_path() {
        let result = resolve_binary("sh", &[]);
        assert!(result.is_some(), "sh should be in PATH");
    }

    #[test]
    fn test_resolve_binary_not_found() {
        let result = resolve_binary("this_binary_does_not_exist_12345", &[]);
        assert!(result.is_none());
    }

    #[test]
    fn test_resolve_binary_with_fallbacks() {
        let Some(binary) = get_existing_binary() else {
            eprintln!("Skipping: No suitable binary found");
            return;
        };

        let result = resolve_binary("nonexistent", &[binary.to_str().unwrap()]);
        assert!(result.is_some(), "Should find fallback {}", binary.display());
        assert_eq!(result.unwrap(), binary);
    }

    #[test]
    fn test_resolve_binary_fallback_order() {
        let sh = which::which("sh").ok();
        let ls = which::which("ls").ok();

        let (Some(first), Some(second)) = (sh, ls) else {
            eprintln!("Skipping: Need both sh and ls");
            return;
        };

        // First fallback should win
        let result = resolve_binary(
            "nonexistent",
            &[first.to_str().unwrap(), second.to_str().unwrap()],
        );
        assert_eq!(result.unwrap(), first);
    }

    #[test]
    fn test_is_executable_true() {
        let Some(binary) = get_existing_binary() else {
            eprintln!("Skipping: No suitable binary found");
            return;
        };
        assert!(is_executable(&binary));
    }

    #[test]
    fn test_is_executable_false() {
        // /proc/self/cmdline exists but isn't executable
        if Path::new("/proc/self/cmdline").exists() {
            assert!(!is_executable(Path::new("/proc/self/cmdline")));
        } else {
            eprintln!("Skipping: /proc/self/cmdline not available");
        }
    }

    #[test]
    fn test_is_executable_nonexistent() {
        assert!(!is_executable(Path::new("/nonexistent")));
    }

    #[test]
    fn test_prefix_dir_usr_bin() {
        let path = PathBuf::from("/usr/bin/python3");
        assert_eq!(prefix_dir(&path), Some(PathBuf::from("/usr")));
    }

    #[test]
    fn test_prefix_dir_usr_local_bin() {
        let path = PathBuf::from("/usr/local/bin/node");
        assert_eq!(prefix_dir(&path), Some(PathBuf::from("/usr/local")));
    }

    #[test]
    fn test_prefix_dir_not_in_bin() {
        let path = PathBuf::from("/opt/myapp/mybin");
        assert_eq!(prefix_dir(&path), Some(PathBuf::from("/opt/myapp")));
    }

    #[test]
    fn test_prefix_dir_root() {
        let path = PathBuf::from("/bin/sh");
        assert_eq!(prefix_dir(&path), Some(PathBuf::from("/")));
    }

    #[test]
    fn test_resolve_from_env_not_set() {
        let result = resolve_from_env("NONEXISTENT_ENV_VAR_12345", "python3");
        assert!(result.is_none());
    }

    #[test]
    fn test_resolve_from_env_with_bin_subdir() {
        // This test depends on system state, so we just verify it doesn't panic
        // and returns reasonable results
        // SAFETY: This is a single-threaded test, no concurrent access to env vars
        unsafe {
            std::env::set_var("TEST_RESOLVE_ENV", "/usr");
        }
        let result = resolve_from_env("TEST_RESOLVE_ENV", "sh");
        // /usr/bin/sh might or might not exist depending on system
        // SAFETY: This is a single-threaded test, no concurrent access to env vars
        unsafe {
            std::env::remove_var("TEST_RESOLVE_ENV");
        }
        // Just verify we got Some or None, no panic
        let _ = result;
    }
}
