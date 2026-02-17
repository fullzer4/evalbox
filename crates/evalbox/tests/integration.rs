//! Integration tests for evalbox.
//!
//! These tests verify the full runtime detection and probing workflow.

use std::path::Path;

use evalbox::{Probe, ProbeCache};

#[cfg(feature = "python")]
mod python_integration {
    use super::*;
    use evalbox::PythonProbe;

    #[test]
    fn test_python_probe_cache_workflow() {
        let cache = ProbeCache::new();
        let probe = PythonProbe::new();

        // Try to detect Python
        let Some(binary) = probe.detect() else {
            // Python not installed, skip test
            eprintln!("Skipping: Python not found");
            return;
        };

        // First probe - should populate cache
        let result1 = cache.get_or_probe(&probe, &binary);
        assert!(result1.is_ok(), "First probe should succeed");
        assert_eq!(cache.len(), 1, "Cache should have one entry");

        // Second probe - should hit cache
        let result2 = cache.get_or_probe(&probe, &binary);
        assert!(result2.is_ok(), "Second probe should succeed");

        // Results should be identical
        let info1 = result1.unwrap();
        let info2 = result2.unwrap();
        assert_eq!(info1.binary, info2.binary);
        assert_eq!(info1.mounts.len(), info2.mounts.len());
    }

    #[test]
    fn test_python_runtime_info_valid() {
        let probe = PythonProbe::new();

        let Some(binary) = probe.detect() else {
            eprintln!("Skipping: Python not found");
            return;
        };

        let info = probe.probe(&binary).expect("Probe should succeed");

        // Verify runtime info
        assert!(info.binary.exists(), "Binary should exist");
        assert!(!info.mounts.is_empty(), "Should have mounts");

        // All mount sources should exist
        for mount in &info.mounts {
            assert!(
                mount.source.exists(),
                "Mount source should exist: {}",
                mount.source.display()
            );
        }

        // Should have PYTHONHOME set
        assert!(info.env.contains_key("PYTHONHOME"), "Should set PYTHONHOME");
    }
}

#[cfg(feature = "go")]
mod go_integration {
    use super::*;
    use evalbox::GoProbe;

    #[test]
    fn test_go_probe_cache_workflow() {
        let cache = ProbeCache::new();
        let probe = GoProbe::new();

        let Some(binary) = probe.detect() else {
            eprintln!("Skipping: Go not found");
            return;
        };

        // First probe
        let result1 = cache.get_or_probe(&probe, &binary);
        assert!(result1.is_ok(), "First probe should succeed");

        // Second probe - cache hit
        let result2 = cache.get_or_probe(&probe, &binary);
        assert!(result2.is_ok(), "Second probe should succeed");

        let info1 = result1.unwrap();
        let info2 = result2.unwrap();
        assert_eq!(info1.binary, info2.binary);
    }

    #[test]
    fn test_go_runtime_info_valid() {
        let probe = GoProbe::new();

        let Some(binary) = probe.detect() else {
            eprintln!("Skipping: Go not found");
            return;
        };

        let info = probe.probe(&binary).expect("Probe should succeed");

        // Verify runtime info
        assert!(info.binary.exists(), "Binary should exist");
        assert!(!info.mounts.is_empty(), "Should have mounts");

        // Should have GOROOT set
        assert!(info.env.contains_key("GOROOT"), "Should set GOROOT");

        // GOROOT mount should exist
        let goroot = &info.env["GOROOT"];
        assert!(
            Path::new(goroot).exists(),
            "GOROOT should exist: {goroot}"
        );
    }

}
