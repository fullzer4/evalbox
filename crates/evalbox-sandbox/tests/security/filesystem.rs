//! Filesystem isolation tests.
//!
//! These tests verify that sandboxed processes cannot access
//! files outside their allowed mounts.

use std::time::Duration;

use evalbox_sandbox::{Executor, Plan};

use crate::common::skip_if_no_namespaces;

/// Test that /etc/shadow is not accessible.
/// This file contains password hashes and should never be readable.
#[test]
#[ignore]
fn test_cannot_read_etc_shadow() {
    if skip_if_no_namespaces() {
        return;
    }

    let output = Executor::run(Plan::new(["cat", "/etc/shadow"]).timeout(Duration::from_secs(5)))
        .expect("Executor should run");

    assert!(!output.success(), "/etc/shadow should not be readable");

    let stderr = output.stderr_str();
    assert!(
        stderr.contains("No such file") || stderr.contains("Permission denied"),
        "Expected 'No such file' or 'Permission denied', got: {}",
        stderr
    );
}

/// Test that /etc/passwd cannot be written to.
#[test]
#[ignore]
fn test_cannot_write_etc_passwd() {
    if skip_if_no_namespaces() {
        return;
    }

    let output = Executor::run(
        Plan::new(["sh", "-c", "echo 'hacked:x:0:0::/:/bin/sh' >> /etc/passwd"])
            .timeout(Duration::from_secs(5)),
    )
    .expect("Executor should run");

    assert!(!output.success(), "/etc/passwd should not be writable");
}

/// Test that /root is not accessible.
#[test]
#[ignore]
fn test_cannot_access_root_home() {
    if skip_if_no_namespaces() {
        return;
    }

    let output = Executor::run(Plan::new(["ls", "/root"]).timeout(Duration::from_secs(5)))
        .expect("Executor should run");

    assert!(!output.success(), "/root should not be accessible");
}

/// Test that the work directory is writable.
#[test]
#[ignore]
fn test_work_dir_is_writable() {
    if skip_if_no_namespaces() {
        return;
    }

    let output = Executor::run(
        Plan::new([
            "sh",
            "-c",
            "echo 'test content' > /work/test.txt && cat /work/test.txt",
        ])
        .timeout(Duration::from_secs(5)),
    )
    .expect("Executor should run");

    assert!(output.success(), "Should be able to write to /work");
    assert_eq!(output.stdout_str().trim(), "test content");
}

/// Test that /tmp is writable.
#[test]
#[ignore]
fn test_tmp_is_writable() {
    if skip_if_no_namespaces() {
        return;
    }

    let output = Executor::run(
        Plan::new([
            "sh",
            "-c",
            "echo 'temp data' > /tmp/test.txt && cat /tmp/test.txt",
        ])
        .timeout(Duration::from_secs(5)),
    )
    .expect("Executor should run");

    assert!(output.success(), "Should be able to write to /tmp");
    assert_eq!(output.stdout_str().trim(), "temp data");
}

/// Test that path traversal attempts are blocked.
///
/// The sandbox creates a minimal /etc with only essential files (passwd, group, hosts).
/// Path traversal should only see the sandbox's minimal /etc, not the host's.
#[test]
#[ignore]
fn test_path_traversal_blocked() {
    if skip_if_no_namespaces() {
        return;
    }

    let output = Executor::run(
        Plan::new(["cat", "/work/../../../etc/passwd"]).timeout(Duration::from_secs(5)),
    )
    .expect("Executor should run");

    // The path resolves to /etc/passwd which is the sandbox's minimal passwd
    if output.success() {
        let content = output.stdout_str();

        // Verify this is NOT the real host passwd
        // Real passwd would have many entries (root, daemon, bin, etc.)
        let line_count = content.lines().count();
        let has_nixbld = content.contains("nixbld"); // NixOS specific
        let has_root = content.contains("root:");
        let has_real_users = content.contains("daemon:") || content.contains("bin:");

        assert!(
            !has_nixbld && !has_real_users && line_count <= 5,
            "Path traversal should not leak real /etc/passwd.\n\
             Expected minimal sandbox passwd, got {} lines:\n{}",
            line_count,
            content
        );

        // If there's root: it should be the sandbox's nobody-only passwd
        if has_root {
            panic!(
                "Path traversal leaked real /etc/passwd with root entry:\n{}",
                content
            );
        }
    }
}

/// Test that symlink attacks are prevented.
#[test]
#[ignore]
fn test_symlink_escape_blocked() {
    if skip_if_no_namespaces() {
        return;
    }

    let output = Executor::run(
        Plan::new([
            "sh",
            "-c",
            "ln -s /etc/shadow /work/shadow && cat /work/shadow",
        ])
        .timeout(Duration::from_secs(5)),
    )
    .expect("Executor should run");

    // Either symlink creation fails or reading it fails
    assert!(!output.success(), "Symlink escape should be blocked");
}

/// Test that /proc/self/exe cannot be used to escape.
#[test]
#[ignore]
fn test_proc_self_exe_safe() {
    if skip_if_no_namespaces() {
        return;
    }

    let output =
        Executor::run(Plan::new(["readlink", "/proc/self/exe"]).timeout(Duration::from_secs(5)))
            .expect("Executor should run");

    // Should not reveal host paths
    if output.success() {
        let exe_path = output.stdout_str();
        assert!(
            !exe_path.contains("/home/") && !exe_path.contains("/usr/"),
            "/proc/self/exe should not reveal host paths: {}",
            exe_path
        );
    }
}
