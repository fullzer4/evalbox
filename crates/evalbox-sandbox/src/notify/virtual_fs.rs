//! Virtual filesystem path translation.
//!
//! Maps paths from the child's perspective to real paths on the host.
//! Used by the supervisor in `Virtualize` mode to translate filesystem
//! syscalls to the correct workspace paths.
//!
//! ## Default Mappings
//!
//! | Child sees | Host path |
//! |-----------|-----------|
//! | `/work` | `{workspace}/work` |
//! | `/tmp` | `{workspace}/tmp` |
//! | `/home` | `{workspace}/home` |

use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Virtual filesystem with path translation.
#[derive(Debug, Clone)]
pub struct VirtualFs {
    /// Maps virtual prefix → real prefix.
    mappings: HashMap<PathBuf, PathBuf>,
}

impl VirtualFs {
    /// Create a new `VirtualFs` with default mappings for the given workspace root.
    pub fn new(workspace_root: &Path) -> Self {
        let mut mappings = HashMap::new();
        mappings.insert(PathBuf::from("/work"), workspace_root.join("work"));
        mappings.insert(PathBuf::from("/tmp"), workspace_root.join("tmp"));
        mappings.insert(PathBuf::from("/home"), workspace_root.join("home"));
        Self { mappings }
    }

    /// Create an empty `VirtualFs` with no mappings.
    pub fn empty() -> Self {
        Self {
            mappings: HashMap::new(),
        }
    }

    /// Add a path mapping.
    pub fn add_mapping(&mut self, virtual_path: impl Into<PathBuf>, real_path: impl Into<PathBuf>) {
        self.mappings.insert(virtual_path.into(), real_path.into());
    }

    /// Translate a path from child's view to host's view.
    ///
    /// Returns `Some(real_path)` if the path matches a mapping,
    /// `None` if the path should be accessed as-is (passthrough).
    pub fn translate(&self, path: &str) -> Option<PathBuf> {
        let path = Path::new(path);
        for (virtual_prefix, real_prefix) in &self.mappings {
            if let Ok(suffix) = path.strip_prefix(virtual_prefix) {
                return Some(real_prefix.join(suffix));
            }
        }
        None
    }

    /// Check if a path is within any allowed scope.
    ///
    /// In `Virtualize` mode, only paths within mappings or system paths are allowed.
    pub fn is_allowed(&self, path: &str) -> bool {
        let path = Path::new(path);

        // Check virtual mappings
        for virtual_prefix in self.mappings.keys() {
            if path.starts_with(virtual_prefix) {
                return true;
            }
        }

        // Allow common system paths (read-only, handled by Landlock)
        let system_prefixes = ["/usr", "/bin", "/lib", "/lib64", "/etc", "/proc", "/dev"];
        for prefix in &system_prefixes {
            if path.starts_with(prefix) {
                return true;
            }
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_mappings() {
        let vfs = VirtualFs::new(Path::new("/tmp/evalbox-abc123"));

        assert_eq!(
            vfs.translate("/work/main.py"),
            Some(PathBuf::from("/tmp/evalbox-abc123/work/main.py"))
        );
        assert_eq!(
            vfs.translate("/tmp/output.txt"),
            Some(PathBuf::from("/tmp/evalbox-abc123/tmp/output.txt"))
        );
        assert_eq!(
            vfs.translate("/home/.bashrc"),
            Some(PathBuf::from("/tmp/evalbox-abc123/home/.bashrc"))
        );
    }

    #[test]
    fn no_translation_for_system_paths() {
        let vfs = VirtualFs::new(Path::new("/tmp/evalbox-abc123"));
        assert_eq!(vfs.translate("/usr/bin/python3"), None);
        assert_eq!(vfs.translate("/etc/passwd"), None);
    }

    #[test]
    fn is_allowed_checks() {
        let vfs = VirtualFs::new(Path::new("/tmp/evalbox-abc123"));

        assert!(vfs.is_allowed("/work/test.py"));
        assert!(vfs.is_allowed("/tmp/output"));
        assert!(vfs.is_allowed("/usr/bin/python3"));
        assert!(vfs.is_allowed("/etc/passwd"));
        assert!(vfs.is_allowed("/proc/self/status"));
        assert!(!vfs.is_allowed("/root/.ssh/id_rsa"));
        assert!(!vfs.is_allowed("/var/log/syslog"));
    }

    #[test]
    fn custom_mapping() {
        let mut vfs = VirtualFs::empty();
        vfs.add_mapping("/data", "/mnt/shared/data");

        assert_eq!(
            vfs.translate("/data/file.csv"),
            Some(PathBuf::from("/mnt/shared/data/file.csv"))
        );
        assert_eq!(vfs.translate("/work/test"), None);
    }
}
