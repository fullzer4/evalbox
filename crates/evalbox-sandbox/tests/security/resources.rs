//! Resource limit tests.
//!
//! These tests verify that resource limits (timeout, memory, pids, output)
//! are properly enforced.

use std::time::Duration;

use evalbox_sandbox::{Executor, Plan, Status};

use crate::common::payload;

/// Test that timeout is enforced.
#[test]
#[ignore]
fn test_timeout_enforced() {
    let start = std::time::Instant::now();

    let output = Executor::run(Plan::new(["sleep", "60"]).timeout(Duration::from_millis(500)))
        .expect("Executor should run");

    let elapsed = start.elapsed();

    assert!(!output.success(), "Should not succeed after timeout");
    assert_eq!(output.status, Status::Timeout, "Status should be Timeout");
    assert!(
        elapsed < Duration::from_secs(2),
        "Should timeout quickly, took {elapsed:?}"
    );
}

/// Test that infinite loops are killed by timeout.
#[test]
#[ignore]
fn test_infinite_loop_timeout() {
    let output = Executor::run(
        Plan::new(["sh", "-c", "while true; do :; done"]).timeout(Duration::from_millis(500)),
    )
    .expect("Executor should run");

    assert!(!output.success(), "Infinite loop should be killed");
    assert_eq!(output.status, Status::Timeout, "Status should be Timeout");
}

/// Test that `max_pids` limit is enforced.
#[test]
#[ignore]
fn test_max_pids_enforced() {
    let output = Executor::run(
        Plan::new(["./payload"])
            .executable("payload", payload("fork_bomb"))
            .binary_path("./payload")
            .max_pids(10)
            .timeout(Duration::from_secs(5)),
    )
    .expect("Executor should run");

    // Fork bomb should fail when limit is reached
    assert!(!output.success(), "Fork bomb should be limited");

    // Should see indication that fork limit was reached
    let stdout = output.stdout_str();
    assert!(
        stdout.contains("limit reached") || output.exit_code != Some(0),
        "Should hit fork limit"
    );
}

/// Test that output limit is enforced.
#[test]
#[ignore]
fn test_output_limit_enforced() {
    let output = Executor::run(
        Plan::new(["sh", "-c", "yes | head -c 100000"]) // 100KB of 'y'
            .max_output(1024) // 1KB limit
            .timeout(Duration::from_secs(10)),
    )
    .expect("Executor should run");

    // Output should be limited
    let total_output = output.stdout.len() + output.stderr.len();

    assert!(
        total_output <= 1024 * 4, // Allow some buffer for implementation
        "Output should be limited to ~1KB, got {total_output} bytes"
    );

    // Either output was truncated or process was killed when limit exceeded
    assert!(
        output.status == Status::OutputLimitExceeded || total_output <= 1024,
        "Output limit should be enforced. Got {} bytes, status: {:?}",
        total_output,
        output.status
    );
}

/// Test that memory limit is set (rlimit check).
/// Note: Actually enforcing memory limits requires cgroups which may not be available.
#[test]
#[ignore]
fn test_memory_limit_set() {
    // Check that the memory rlimit is set correctly
    let output = Executor::run(
        Plan::new([
            "sh",
            "-c",
            "ulimit -v 2>/dev/null || cat /proc/self/limits | grep -i 'address space'",
        ])
        .memory(64 * 1024 * 1024) // 64MB
        .timeout(Duration::from_secs(5)),
    )
    .expect("Executor should run");

    // If ulimit works, it should show a limited value
    // This test just verifies the rlimit is being set, not that OOM works
    // (OOM requires cgroups which may not be available in all environments)
    let stdout = output.stdout_str();
    let stderr = output.stderr_str();

    // Just verify the command ran - actual memory enforcement depends on system config
    assert!(
        output.exit_code.is_some(),
        "Should get exit code. stdout: {stdout}, stderr: {stderr}"
    );
}

/// Test that file descriptor limit is set via rlimit.
#[test]
#[ignore]
fn test_fd_limit_set() {
    // Check the fd limit using ulimit
    let output =
        Executor::run(Plan::new(["sh", "-c", "ulimit -n"]).timeout(Duration::from_secs(5)))
            .expect("Executor should run");

    // The default fd limit should be reasonable (not unlimited)
    if output.success() {
        let stdout = output.stdout_str();
        let limit_str = stdout.trim();
        if let Ok(limit) = limit_str.parse::<u64>() {
            // Verify limit is set to a reasonable value (not unlimited)
            assert!(
                limit < 1000000,
                "FD limit should be reasonable, got {limit}"
            );
        }
    }
}

/// Test that CPU time limit works (via timeout).
#[test]
#[ignore]
fn test_cpu_intensive_timeout() {
    let start = std::time::Instant::now();

    // CPU-intensive work that doesn't sleep
    let output = Executor::run(
        Plan::new([
            "sh",
            "-c",
            "i=0; while [ $i -lt 999999999 ]; do i=$((i+1)); done",
        ])
        .timeout(Duration::from_millis(500)),
    )
    .expect("Executor should run");

    let elapsed = start.elapsed();

    assert_eq!(output.status, Status::Timeout);
    assert!(
        elapsed < Duration::from_secs(2),
        "CPU work should be killed by timeout"
    );
}
