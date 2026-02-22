//! Network isolation tests.
//!
//! These tests verify that network access is properly blocked
//! when not explicitly enabled.

use std::time::Duration;

use evalbox_sandbox::{Executor, Plan};

/// Test that network is blocked by default.
/// curl should fail to connect to any external host.
#[test]
#[ignore]
fn test_network_blocked_by_default() {
    let output = Executor::run(
        Plan::new(["sh", "-c", "curl -s --connect-timeout 2 http://example.com || wget -q -O- --timeout=2 http://example.com"])
            .timeout(Duration::from_secs(5)),
    )
    .expect("Executor should run");

    assert!(!output.success(), "Network should be blocked by default");
}

/// Test that localhost connections are blocked.
#[test]
#[ignore]
fn test_localhost_blocked() {
    let output = Executor::run(
        Plan::new(["sh", "-c", "echo test | nc -w1 127.0.0.1 80 2>/dev/null"])
            .timeout(Duration::from_secs(5)),
    )
    .expect("Executor should run");

    // Should fail - seccomp blocks socket creation
    assert!(!output.success(), "Localhost should not be reachable");
}

/// Test that external DNS resolution fails when network is blocked.
/// Note: /etc/hosts lookups may still work since the file exists on the host.
#[test]
#[ignore]
fn test_external_dns_blocked() {
    // Use a domain that definitely isn't in /etc/hosts
    let output = Executor::run(
        Plan::new([
            "sh",
            "-c",
            "getent hosts randomdomain12345.example.com 2>&1",
        ])
        .timeout(Duration::from_secs(5)),
    )
    .expect("Executor should run");

    // Should fail - no network means no DNS server access
    // Note: This might "succeed" with an error message if getent exists
    let stdout = output.stdout_str();
    let stderr = output.stderr_str();

    // Verify no actual IP was resolved
    let has_ip = stdout.contains('.') && stdout.chars().any(|c| c.is_ascii_digit());
    assert!(
        !has_ip || !output.success(),
        "External DNS should not resolve. stdout: {stdout}, stderr: {stderr}"
    );
}

/// Test that network flag can be enabled without breaking execution.
/// Note: Actual network connectivity depends on host network availability.
#[test]
#[ignore]
fn test_network_flag_enabled() {
    // Just verify that enabling network doesn't break sandbox execution
    let output = Executor::run(
        Plan::new(["sh", "-c", "echo 'network flag test'"])
            .network(true)
            .timeout(Duration::from_secs(5)),
    )
    .expect("Executor should run");

    assert!(
        output.success(),
        "Basic command should work with network enabled"
    );
    assert!(
        output.stdout_str().contains("network flag test"),
        "Should see output"
    );
}

/// Test that the loopback interface exists but is isolated.
#[test]
#[ignore]
fn test_loopback_isolated() {
    let output = Executor::run(
        Plan::new([
            "sh",
            "-c",
            "ip addr show lo 2>/dev/null || ifconfig lo 2>/dev/null",
        ])
        .timeout(Duration::from_secs(5)),
    )
    .expect("Executor should run");

    // Without network namespaces, the host loopback is visible but
    // seccomp blocks socket creation so it can't be used to connect.
    // This is more of a sanity check that the command runs.
    if output.success() {
        let stdout = output.stdout_str();
        assert!(
            stdout.contains("lo") || stdout.contains("127.0.0.1"),
            "Loopback should be visible"
        );
    }
}
