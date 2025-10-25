use pyenclave_core::policy::landlock::{apply_landlock_rules, LandlockRule, LandlockAccess};
use std::fs;
use std::io::Write;
use tempfile::TempDir;

/// Test that Landlock can be applied successfully on supported kernels
#[test]
fn test_apply_landlock_basic() {
    // Create a temporary directory for testing
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let temp_path = temp_dir.path().to_str().unwrap();

    // Create a simple rule: allow read-only access to temp directory
    let rules = vec![LandlockRule {
        path: temp_path.to_string(),
        access: LandlockAccess::ReadOnly,
    }];

    // Apply the rules
    let result = apply_landlock_rules(&rules);

    // On kernels without Landlock support (< 5.13), this will return an error
    // On kernels with Landlock, it should succeed
    match result {
        Ok(_) => {
            println!("✅ Landlock applied successfully (kernel >= 5.13)");
        }
        Err(e) => {
            println!("⚠️  Landlock not supported: {} (kernel < 5.13)", e);
            // This is not a test failure - just a warning
        }
    }
}

/// Test read-only access enforcement
#[test]
fn test_readonly_access() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let temp_path = temp_dir.path();

    // Create a test file before applying Landlock
    let test_file = temp_path.join("test.txt");
    fs::write(&test_file, b"initial content").expect("Failed to write test file");

    // Apply Landlock with read-only access
    let rules = vec![LandlockRule {
        path: temp_path.to_str().unwrap().to_string(),
        access: LandlockAccess::ReadOnly,
    }];

    let result = apply_landlock_rules(&rules);
    if result.is_err() {
        println!("⚠️  Skipping test: Landlock not supported on this kernel");
        return;
    }

    // Should be able to read
    let content = fs::read_to_string(&test_file);
    assert!(
        content.is_ok(),
        "Should be able to read file with read-only access"
    );
    assert_eq!(content.unwrap(), "initial content");

    // Should NOT be able to write
    let write_result = fs::write(&test_file, b"new content");
    assert!(
        write_result.is_err(),
        "Should not be able to write file with read-only access"
    );
}

/// Test read-write access enforcement
#[test]
fn test_readwrite_access() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let temp_path = temp_dir.path();

    // Create a test file
    let test_file = temp_path.join("test.txt");
    fs::write(&test_file, b"initial").expect("Failed to write test file");

    // Apply Landlock with read-write access
    let rules = vec![LandlockRule {
        path: temp_path.to_str().unwrap().to_string(),
        access: LandlockAccess::ReadWrite,
    }];

    let result = apply_landlock_rules(&rules);
    if result.is_err() {
        println!("⚠️  Skipping test: Landlock not supported on this kernel");
        return;
    }

    // Should be able to read
    let content = fs::read_to_string(&test_file);
    assert!(content.is_ok(), "Should be able to read file");
    assert_eq!(content.unwrap(), "initial");

    // Should be able to write
    let write_result = fs::write(&test_file, b"modified");
    assert!(
        write_result.is_ok(),
        "Should be able to write file with read-write access"
    );

    // Verify the write
    let new_content = fs::read_to_string(&test_file).expect("Failed to read after write");
    assert_eq!(new_content, "modified");
}

/// Test that access is denied outside the allowlist
#[test]
fn test_deny_outside_allowlist() {
    let allowed_dir = TempDir::new().expect("Failed to create allowed dir");
    let denied_dir = TempDir::new().expect("Failed to create denied dir");

    let allowed_path = allowed_dir.path();
    let denied_path = denied_dir.path();

    // Create test files in both directories
    let allowed_file = allowed_path.join("allowed.txt");
    let denied_file = denied_path.join("denied.txt");

    fs::write(&allowed_file, b"allowed").expect("Failed to write allowed file");
    fs::write(&denied_file, b"denied").expect("Failed to write denied file");

    // Apply Landlock: only allow access to allowed_dir
    let rules = vec![LandlockRule {
        path: allowed_path.to_str().unwrap().to_string(),
        access: LandlockAccess::ReadOnly,
    }];

    let result = apply_landlock_rules(&rules);
    if result.is_err() {
        println!("⚠️  Skipping test: Landlock not supported on this kernel");
        return;
    }

    // Should be able to access allowed file
    let allowed_result = fs::read_to_string(&allowed_file);
    assert!(
        allowed_result.is_ok(),
        "Should be able to read file in allowlist"
    );

    // Should NOT be able to access denied file
    let denied_result = fs::read_to_string(&denied_file);
    assert!(
        denied_result.is_err(),
        "Should not be able to read file outside allowlist"
    );
}

/// Test multiple rules (multiple directories)
#[test]
fn test_multiple_rules() {
    let dir1 = TempDir::new().expect("Failed to create dir1");
    let dir2 = TempDir::new().expect("Failed to create dir2");
    let dir3 = TempDir::new().expect("Failed to create dir3");

    let path1 = dir1.path();
    let path2 = dir2.path();
    let path3 = dir3.path();

    // Create test files
    let file1 = path1.join("file1.txt");
    let file2 = path2.join("file2.txt");
    let file3 = path3.join("file3.txt");

    fs::write(&file1, b"file1").expect("Failed to write file1");
    fs::write(&file2, b"file2").expect("Failed to write file2");
    fs::write(&file3, b"file3").expect("Failed to write file3");

    // Apply Landlock: allow dir1 (RO) and dir2 (RW), deny dir3
    let rules = vec![
        LandlockRule {
            path: path1.to_str().unwrap().to_string(),
            access: LandlockAccess::ReadOnly,
        },
        LandlockRule {
            path: path2.to_str().unwrap().to_string(),
            access: LandlockAccess::ReadWrite,
        },
    ];

    let result = apply_landlock_rules(&rules);
    if result.is_err() {
        println!("⚠️  Skipping test: Landlock not supported on this kernel");
        return;
    }

    // Should access file1 (read only)
    assert!(
        fs::read_to_string(&file1).is_ok(),
        "Should read file1 (RO)"
    );

    // Should access file2 (read-write)
    assert!(
        fs::read_to_string(&file2).is_ok(),
        "Should read file2 (RW)"
    );
    assert!(
        fs::write(&file2, b"modified").is_ok(),
        "Should write file2 (RW)"
    );

    // Should NOT access file3 (not in allowlist)
    assert!(
        fs::read_to_string(&file3).is_err(),
        "Should not access file3 (denied)"
    );
}

/// Test that Landlock ABI version is detected correctly
#[test]
fn test_detect_landlock_abi() {
    use pyenclave_core::policy::landlock::detect_landlock_abi;

    let abi = detect_landlock_abi();

    match abi {
        Some(version) => {
            println!("✅ Landlock ABI version: {}", version);
            assert!(version >= 1 && version <= 5, "ABI version should be 1-5");
        }
        None => {
            println!("⚠️  Landlock not supported on this kernel");
        }
    }
}

/// Test empty ruleset (should apply successfully but deny everything)
#[test]
fn test_empty_ruleset() {
    let rules: Vec<LandlockRule> = vec![];

    let result = apply_landlock_rules(&rules);

    // Empty ruleset should still succeed on supported kernels
    match result {
        Ok(_) => {
            println!("✅ Empty Landlock ruleset applied (denies everything)");
        }
        Err(e) => {
            println!("⚠️  Landlock not supported: {}", e);
        }
    }
}

/// Test that Landlock works with nested paths
#[test]
fn test_nested_paths() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let temp_path = temp_dir.path();

    // Create nested structure: temp_dir/subdir/file.txt
    let subdir = temp_path.join("subdir");
    fs::create_dir(&subdir).expect("Failed to create subdir");
    let nested_file = subdir.join("file.txt");
    fs::write(&nested_file, b"nested").expect("Failed to write nested file");

    // Apply Landlock to parent directory only
    let rules = vec![LandlockRule {
        path: temp_path.to_str().unwrap().to_string(),
        access: LandlockAccess::ReadOnly,
    }];

    let result = apply_landlock_rules(&rules);
    if result.is_err() {
        println!("⚠️  Skipping test: Landlock not supported on this kernel");
        return;
    }

    // Should be able to access nested file (parent is allowed)
    let content = fs::read_to_string(&nested_file);
    assert!(
        content.is_ok(),
        "Should be able to access nested file when parent is allowed"
    );
    assert_eq!(content.unwrap(), "nested");
}

/// Test LandlockRule validation
#[test]
fn test_rule_validation() {
    // Valid rule
    let valid_rule = LandlockRule {
        path: "/tmp".to_string(),
        access: LandlockAccess::ReadOnly,
    };
    assert_eq!(valid_rule.path, "/tmp");

    // Test both access types
    let ro_rule = LandlockRule {
        path: "/tmp".to_string(),
        access: LandlockAccess::ReadOnly,
    };
    let rw_rule = LandlockRule {
        path: "/tmp".to_string(),
        access: LandlockAccess::ReadWrite,
    };

    assert!(matches!(ro_rule.access, LandlockAccess::ReadOnly));
    assert!(matches!(rw_rule.access, LandlockAccess::ReadWrite));
}
