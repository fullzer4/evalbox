//! Filesystem isolation tests.
//!
//! These tests verify that sandboxed processes cannot access
//! files outside their Landlock-allowed paths.
//!
//! Without `pivot_root`, the child process chdir's to `{workspace}/work`.
//! Landlock restricts filesystem access to only allowed paths.

use std::time::Duration;

use evalbox_sandbox::{Executor, Plan};

/// Test that /etc/shadow is not accessible.
/// Landlock only grants read access to /etc, and /etc/shadow requires root.
#[test]
#[ignore]
fn test_cannot_read_etc_shadow() {
    let output = Executor::run(Plan::new(["cat", "/etc/shadow"]).timeout(Duration::from_secs(5)))
        .expect("Executor should run");

    assert!(!output.success(), "/etc/shadow should not be readable");

    let stderr = output.stderr_str();
    assert!(
        stderr.contains("No such file") || stderr.contains("Permission denied"),
        "Expected 'No such file' or 'Permission denied', got: {stderr}"
    );
}

/// Test that /etc/passwd cannot be written to.
/// Landlock grants read-only access to /etc, so writes should be blocked.
#[test]
#[ignore]
fn test_cannot_write_etc_passwd() {
    let output = Executor::run(
        Plan::new(["sh", "-c", "echo 'hacked:x:0:0::/:/bin/sh' >> /etc/passwd"])
            .timeout(Duration::from_secs(5)),
    )
    .expect("Executor should run");

    assert!(!output.success(), "/etc/passwd should not be writable");
}

/// Test that /root is not accessible.
/// Landlock has no rule for /root, so access should be denied.
#[test]
#[ignore]
fn test_cannot_access_root_home() {
    let output = Executor::run(Plan::new(["ls", "/root"]).timeout(Duration::from_secs(5)))
        .expect("Executor should run");

    assert!(!output.success(), "/root should not be accessible");
}

/// Test that the work directory (CWD) is writable.
/// The child chdir's to {workspace}/work, which Landlock grants read/write access to.
#[test]
#[ignore]
fn test_work_dir_is_writable() {
    let output = Executor::run(
        Plan::new([
            "sh",
            "-c",
            "echo 'test content' > ./test.txt && cat ./test.txt",
        ])
        .timeout(Duration::from_secs(5)),
    )
    .expect("Executor should run");

    assert!(output.success(), "Should be able to write to CWD (work dir)");
    assert_eq!(output.stdout_str().trim(), "test content");
}

/// Test that the workspace tmp directory is writable.
/// The workspace tmp dir is at ../tmp relative to CWD ({workspace}/work).
/// Landlock grants read/write access to the workspace root.
#[test]
#[ignore]
fn test_tmp_is_writable() {
    let output = Executor::run(
        Plan::new([
            "sh",
            "-c",
            "echo 'temp data' > ../tmp/test.txt && cat ../tmp/test.txt",
        ])
        .timeout(Duration::from_secs(5)),
    )
    .expect("Executor should run");

    assert!(
        output.success(),
        "Should be able to write to workspace tmp (../tmp)"
    );
    assert_eq!(output.stdout_str().trim(), "temp data");
}

/// Test that path traversal attempts are blocked by Landlock.
///
/// Without `pivot_root`, path traversal from CWD goes up the real filesystem.
/// Landlock should block access to paths outside the allowed set.
#[test]
#[ignore]
fn test_path_traversal_blocked() {
    let output = Executor::run(
        Plan::new(["cat", "../../../etc/shadow"]).timeout(Duration::from_secs(5)),
    )
    .expect("Executor should run");

    // Landlock should block access to /etc/shadow (no read on shadow, even via traversal)
    assert!(
        !output.success(),
        "Path traversal to /etc/shadow should be blocked by Landlock"
    );
}

/// Test that symlink attacks are prevented.
/// Landlock controls access at the kernel level, so symlinks to restricted
/// paths should still be blocked.
#[test]
#[ignore]
fn test_symlink_escape_blocked() {
    let output = Executor::run(
        Plan::new([
            "sh",
            "-c",
            "ln -s /etc/shadow ./shadow && cat ./shadow",
        ])
        .timeout(Duration::from_secs(5)),
    )
    .expect("Executor should run");

    // Either symlink creation fails or reading the target fails due to Landlock
    assert!(!output.success(), "Symlink escape should be blocked");
}

/// Test that /proc/self/exe is safe.
/// Without `pivot_root`, /proc/self/exe reveals the real binary path on the host.
/// This is expected behavior -- we just verify the sandbox doesn't crash.
#[test]
#[ignore]
fn test_proc_self_exe_safe() {
    let output =
        Executor::run(Plan::new(["readlink", "/proc/self/exe"]).timeout(Duration::from_secs(5)))
            .expect("Executor should run");

    // Without pivot_root, /proc/self/exe will show the real host path.
    // This is expected -- just verify the command runs without crashing.
    assert!(
        output.exit_code.is_some(),
        "/proc/self/exe readlink should complete without crashing"
    );
}
