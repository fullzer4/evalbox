//! Thread-safe cache for runtime probe results.
//!
//! The cache is keyed by a hash of the binary path and its modification time,
//! so it automatically invalidates when the binary changes.

use std::hash::{Hash, Hasher};
use std::path::Path;
use std::time::SystemTime;

use dashmap::DashMap;

use crate::error::ProbeError;
use crate::probe::{Probe, RuntimeInfo};

pub struct ProbeCache {
    cache: DashMap<u64, RuntimeInfo>,
}

impl ProbeCache {
    pub fn new() -> Self {
        Self { cache: DashMap::new() }
    }

    pub fn get_or_probe<P: Probe>(&self, probe: &P, binary: &Path) -> Result<RuntimeInfo, ProbeError> {
        let key = compute_cache_key(binary)?;

        if let Some(info) = self.cache.get(&key) {
            return Ok(info.clone());
        }

        let info = probe.probe(binary)?;
        self.cache.insert(key, info.clone());
        Ok(info)
    }

    pub fn clear(&self) {
        self.cache.clear();
    }

    pub fn len(&self) -> usize {
        self.cache.len()
    }

    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }
}

impl Default for ProbeCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute a cache key from a binary path and its mtime.
fn compute_cache_key(path: &Path) -> Result<u64, ProbeError> {
    let metadata = std::fs::metadata(path)?;
    let mtime = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);

    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    path.hash(&mut hasher);
    mtime.hash(&mut hasher);
    Ok(hasher.finish())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Get two different existing files for testing
    fn get_test_files() -> Option<(PathBuf, PathBuf)> {
        // Try which first (works on all systems including NixOS)
        let sh = which::which("sh").ok()?;
        let ls = which::which("ls").ok()?;
        Some((sh, ls))
    }

    #[test]
    fn test_cache_key_stability() {
        let Some((file, _)) = get_test_files() else {
            eprintln!("Skipping: No suitable test files found");
            return;
        };

        let key1 = compute_cache_key(&file);
        let key2 = compute_cache_key(&file);

        assert!(key1.is_ok(), "Should compute cache key for {}", file.display());
        assert!(key2.is_ok(), "Should compute cache key for {}", file.display());
        assert_eq!(key1.unwrap(), key2.unwrap(), "Same path should give same key");
    }

    #[test]
    fn test_different_paths_different_keys() {
        let Some((file1, file2)) = get_test_files() else {
            eprintln!("Skipping: No suitable test files found");
            return;
        };

        let key1 = compute_cache_key(&file1).unwrap();
        let key2 = compute_cache_key(&file2).unwrap();

        assert_ne!(key1, key2, "Different paths should give different keys");
    }

    #[test]
    fn test_cache_key_nonexistent() {
        let result = compute_cache_key(Path::new("/nonexistent/path"));
        assert!(result.is_err(), "Should fail for nonexistent path");
    }

    #[test]
    fn test_probe_cache_empty() {
        let cache = ProbeCache::new();
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_probe_cache_clear() {
        let cache = ProbeCache::new();
        // We can't easily test get_or_probe without a real probe,
        // but we can test clear on empty cache
        cache.clear();
        assert!(cache.is_empty());
    }

    #[test]
    fn test_probe_cache_default() {
        let cache = ProbeCache::default();
        assert!(cache.is_empty());
    }
}
