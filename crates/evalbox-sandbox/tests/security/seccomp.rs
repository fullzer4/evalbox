//! Seccomp syscall filter tests.
//!
//! These tests verify that dangerous syscalls are blocked by the BPF filter.
//! Blocked syscalls should cause the process to be killed with SIGSYS (signal 31).

use std::time::Duration;

use evalbox_sandbox::{Executor, Plan};

use crate::common::{SIGSYS, payload};

/// Test that a simple payload can execute successfully.
/// This is a control test to verify the sandbox is working.
#[test]
#[ignore]
fn test_payload_can_execute() {
    let output = Executor::run(
        Plan::new(["./payload"])
            .executable("payload", payload("success"))
            .binary_path("./payload")
            .timeout(Duration::from_secs(5)),
    )
    .expect("Executor should run");

    assert!(output.success(), "Control payload should succeed");
    assert!(
        output
            .stdout_str()
            .contains("payload executed successfully"),
        "Should see success message"
    );
}

/// Test that ptrace syscall is blocked.
/// ptrace is used for debugging and can be used to escape sandboxes.
#[test]
#[ignore]
fn test_ptrace_blocked() {
    let output = Executor::run(
        Plan::new(["./payload"])
            .executable("payload", payload("syscall_ptrace"))
            .binary_path("./payload")
            .timeout(Duration::from_secs(5)),
    )
    .expect("Executor should run");

    assert!(!output.success(), "ptrace should be blocked");
    assert_eq!(
        output.signal,
        Some(SIGSYS),
        "Should be killed by SIGSYS, got signal {:?}",
        output.signal
    );
}

/// Test that mount syscall is blocked.
/// mount could be used to remount filesystems and escape isolation.
#[test]
#[ignore]
fn test_mount_blocked() {
    let output = Executor::run(
        Plan::new(["./payload"])
            .executable("payload", payload("syscall_mount"))
            .binary_path("./payload")
            .timeout(Duration::from_secs(5)),
    )
    .expect("Executor should run");

    assert!(!output.success(), "mount should be blocked");
    assert_eq!(
        output.signal,
        Some(SIGSYS),
        "Should be killed by SIGSYS, got signal {:?}",
        output.signal
    );
}

/// Test that reboot syscall is blocked.
/// Obviously we don't want sandboxed code to reboot the system.
#[test]
#[ignore]
fn test_reboot_blocked() {
    let output = Executor::run(
        Plan::new(["./payload"])
            .executable("payload", payload("syscall_reboot"))
            .binary_path("./payload")
            .timeout(Duration::from_secs(5)),
    )
    .expect("Executor should run");

    assert!(!output.success(), "reboot should be blocked");
    assert_eq!(
        output.signal,
        Some(SIGSYS),
        "Should be killed by SIGSYS, got signal {:?}",
        output.signal
    );
}

/// Test that `clone(CLONE_NEWUSER)` is blocked.
/// Creating new namespaces inside sandbox could allow escape.
#[test]
#[ignore]
fn test_clone_newuser_blocked() {
    let output = Executor::run(
        Plan::new(["./payload"])
            .executable("payload", payload("syscall_clone_ns"))
            .binary_path("./payload")
            .timeout(Duration::from_secs(5)),
    )
    .expect("Executor should run");

    assert!(!output.success(), "clone(CLONE_NEWUSER) should be blocked");
    assert_eq!(
        output.signal,
        Some(SIGSYS),
        "Should be killed by SIGSYS, got signal {:?}",
        output.signal
    );
}

/// Test that `AF_NETLINK` sockets are blocked.
/// Netlink gives access to kernel interfaces like `nf_tables` (CVE-2024-1086).
#[test]
#[ignore]
fn test_socket_netlink_blocked() {
    let output = Executor::run(
        Plan::new(["./payload"])
            .executable("payload", payload("socket_netlink"))
            .binary_path("./payload")
            .timeout(Duration::from_secs(5)),
    )
    .expect("Executor should run");

    assert!(!output.success(), "AF_NETLINK should be blocked");
    assert_eq!(
        output.signal,
        Some(SIGSYS),
        "Should be killed by SIGSYS, got signal {:?}",
        output.signal
    );
}

/// Test that `SOCK_RAW` sockets are blocked.
/// Raw sockets allow crafting arbitrary packets.
#[test]
#[ignore]
fn test_socket_raw_blocked() {
    let output = Executor::run(
        Plan::new(["./payload"])
            .executable("payload", payload("socket_raw"))
            .binary_path("./payload")
            .timeout(Duration::from_secs(5)),
    )
    .expect("Executor should run");

    assert!(!output.success(), "SOCK_RAW should be blocked");
    assert_eq!(
        output.signal,
        Some(SIGSYS),
        "Should be killed by SIGSYS, got signal {:?}",
        output.signal
    );
}

/// Test that keyctl syscall is blocked.
/// Kernel keyring is not namespaced and could leak secrets.
/// CVE-2016-0728 used keyctl for privilege escalation.
#[test]
#[ignore]
fn test_keyctl_blocked() {
    let output = Executor::run(
        Plan::new(["./payload"])
            .executable("payload", payload("syscall_keyctl"))
            .binary_path("./payload")
            .timeout(Duration::from_secs(5)),
    )
    .expect("Executor should run");

    assert!(!output.success(), "keyctl should be blocked");
    assert_eq!(
        output.signal,
        Some(SIGSYS),
        "Should be killed by SIGSYS, got signal {:?}",
        output.signal
    );
}

/// Test that bpf syscall is blocked.
/// eBPF is a massive kernel attack surface with many CVEs.
/// CVE-2021-3490, CVE-2022-23222, etc.
#[test]
#[ignore]
fn test_bpf_blocked() {
    let output = Executor::run(
        Plan::new(["./payload"])
            .executable("payload", payload("syscall_bpf"))
            .binary_path("./payload")
            .timeout(Duration::from_secs(5)),
    )
    .expect("Executor should run");

    assert!(!output.success(), "bpf should be blocked");
    assert_eq!(
        output.signal,
        Some(SIGSYS),
        "Should be killed by SIGSYS, got signal {:?}",
        output.signal
    );
}
