//! CVE-specific security tests.
//!
//! These tests verify that the sandbox blocks known vulnerability exploitation
//! techniques from real-world CVEs.

use std::time::Duration;

use evalbox_sandbox::{Executor, Plan};

use crate::common::{SIGSYS, payload};

// =============================================================================
// CVE-2024-1086: nf_tables Use-After-Free
// =============================================================================

/// Test that CVE-2024-1086 attack vector is blocked.
///
/// CVE-2024-1086 is a use-after-free in Linux kernel's `nf_tables`.
/// The exploit requires `AF_NETLINK` socket access to `nf_tables` subsystem.
/// Actively exploited in ransomware campaigns (CISA Oct 2025).
///
/// Reference: <https://www.sysdig.com/blog/detecting-cve-2024-1086>
#[test]
#[ignore]
fn test_cve_2024_1086_nftables_blocked() {
    let output = Executor::run(
        Plan::new(["./payload"])
            .executable("payload", payload("cve_2024_1086_nftables"))
            .binary_path("./payload")
            .timeout(Duration::from_secs(5)),
    )
    .expect("Executor should run");

    // AF_NETLINK socket should trigger SIGSYS
    assert!(
        !output.success() || output.signal == Some(SIGSYS),
        "CVE-2024-1086 attack vector should be blocked. Exit: {:?}, Signal: {:?}",
        output.exit_code,
        output.signal
    );
}

// =============================================================================
// CVE-2022-0185: legacy_parse_param Heap Overflow
// =============================================================================

/// Test that CVE-2022-0185 attack vector is blocked.
///
/// CVE-2022-0185 is a heap overflow in `fsconfig()` syscall.
/// Requires `CAP_SYS_ADMIN` in user namespace.
/// Won $31,337 bounty for escaping Google's kCTF containers.
///
/// Reference: <https://www.willsroot.io/2022/01/cve-2022-0185.html>
#[test]
#[ignore]
fn test_cve_2022_0185_fsconfig_blocked() {
    let output = Executor::run(
        Plan::new(["./payload"])
            .executable("payload", payload("cve_2022_0185_fsconfig"))
            .binary_path("./payload")
            .timeout(Duration::from_secs(5)),
    )
    .expect("Executor should run");

    // Either fsconfig syscall blocked (SIGSYS) or fsopen fails (exit 1)
    assert!(
        !output.success(),
        "CVE-2022-0185 attack vector should be blocked. Exit: {:?}, Signal: {:?}",
        output.exit_code,
        output.signal
    );
}

// =============================================================================
// CVE-2017-5226: TIOCSTI Terminal Injection
// =============================================================================

/// Test that CVE-2017-5226 TIOCSTI attack is blocked.
///
/// TIOCSTI ioctl injects characters into terminal input buffer.
/// Allows sandbox escape by injecting commands into parent shell.
/// Affected bubblewrap, `SELinux` sandbox, util-linux runuser.
///
/// Reference: <https://github.com/containers/bubblewrap/issues/142>
#[test]
#[ignore]
fn test_cve_2017_5226_tiocsti_blocked() {
    let output = Executor::run(
        Plan::new(["./payload"])
            .executable("payload", payload("cve_2017_5226_tiocsti"))
            .binary_path("./payload")
            .timeout(Duration::from_secs(5)),
    )
    .expect("Executor should run");

    // TIOCSTI should either be blocked by seccomp or fail (no tty)
    assert!(
        !output.success() || output.signal == Some(SIGSYS),
        "TIOCSTI should be blocked. Exit: {:?}, Signal: {:?}",
        output.exit_code,
        output.signal
    );
}

// =============================================================================
// CVE-2022-0492: cgroups release_agent Escape
// =============================================================================

/// Test that CVE-2022-0492 cgroups escape is blocked.
///
/// CVE-2022-0492 allows container escape via cgroup `release_agent`.
/// Requires user namespace + mount capability.
/// CVSS 7.0 (High).
///
/// Reference: <https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups>/
#[test]
#[ignore]
fn test_cve_2022_0492_cgroups_blocked() {
    let output = Executor::run(
        Plan::new(["./payload"])
            .executable("payload", payload("cve_2022_0492_cgroups"))
            .binary_path("./payload")
            .timeout(Duration::from_secs(5)),
    )
    .expect("Executor should run");

    // Should fail at clone(CLONE_NEWUSER) or mount()
    assert!(
        !output.success() || output.signal == Some(SIGSYS),
        "CVE-2022-0492 attack should be blocked. Exit: {:?}, Signal: {:?}",
        output.exit_code,
        output.signal
    );
}

// =============================================================================
// Fileless Execution (memfd_create + execveat)
// =============================================================================

/// Test that fileless execution is blocked.
///
/// `memfd_create` + execveat allows executing code without writing to filesystem.
/// Used by malware to evade detection.
/// Bypasses filesystem-based security controls.
///
/// Reference: <https://www.aquasec.com/blog/intro-to-fileless-malware-in-containers>/
#[test]
#[ignore]
fn test_fileless_memfd_blocked() {
    let output = Executor::run(
        Plan::new(["./payload"])
            .executable("payload", payload("fileless_memfd"))
            .binary_path("./payload")
            .timeout(Duration::from_secs(5)),
    )
    .expect("Executor should run");

    // Either memfd_create or execveat should be blocked
    assert!(
        !output.success() || output.signal == Some(SIGSYS),
        "Fileless execution should be blocked. Exit: {:?}, Signal: {:?}",
        output.exit_code,
        output.signal
    );
}

// =============================================================================
// Dangerous ioctls
// =============================================================================

/// Test that TIOCLINUX ioctl is blocked.
///
/// TIOCLINUX allows virtual console manipulation and input injection.
/// Similar attack vector to TIOCSTI but for virtual consoles.
#[test]
#[ignore]
fn test_ioctl_tioclinux_blocked() {
    let output = Executor::run(
        Plan::new(["./payload"])
            .executable("payload", payload("ioctl_tioclinux"))
            .binary_path("./payload")
            .timeout(Duration::from_secs(5)),
    )
    .expect("Executor should run");

    assert!(
        !output.success() || output.signal == Some(SIGSYS),
        "TIOCLINUX should be blocked. Exit: {:?}, Signal: {:?}",
        output.exit_code,
        output.signal
    );
}

/// Test that TIOCSETD ioctl is blocked.
///
/// TIOCSETD loads TTY line disciplines which have had many vulnerabilities:
/// - CVE-2017-2636: `n_hdlc` double-free
/// - CVE-2019-11815: slip line discipline race
/// - Multiple other line discipline bugs
#[test]
#[ignore]
fn test_ioctl_tiocsetd_blocked() {
    let output = Executor::run(
        Plan::new(["./payload"])
            .executable("payload", payload("ioctl_tiocsetd"))
            .binary_path("./payload")
            .timeout(Duration::from_secs(5)),
    )
    .expect("Executor should run");

    assert!(
        !output.success() || output.signal == Some(SIGSYS),
        "TIOCSETD should be blocked. Exit: {:?}, Signal: {:?}",
        output.exit_code,
        output.signal
    );
}

// =============================================================================
// User Namespace Creation
// =============================================================================

/// Test that user namespace creation is blocked.
///
/// User namespaces are the prerequisite for most kernel exploits:
/// - CVE-2024-1086, CVE-2022-0185, CVE-2022-0492, CVE-2021-22555
///
/// Blocking `clone(CLONE_NEWUSER)` prevents a large class of kernel exploits.
#[test]
#[ignore]
fn test_userns_creation_blocked() {
    let output = Executor::run(
        Plan::new(["./payload"])
            .executable("payload", payload("userns_escape"))
            .binary_path("./payload")
            .timeout(Duration::from_secs(5)),
    )
    .expect("Executor should run");

    assert!(
        !output.success() || output.signal == Some(SIGSYS),
        "User namespace creation should be blocked. Exit: {:?}, Signal: {:?}",
        output.exit_code,
        output.signal
    );
}

// =============================================================================
// ptrace
// =============================================================================

/// Test that ptrace is blocked.
///
/// ptrace allows process debugging/injection:
/// - Read/write process memory
/// - Inject code
/// - Bypass security controls in traced process
///
/// CVE-2019-13272: ptrace `PTRACE_TRACEME` privilege escalation
#[test]
#[ignore]
fn test_ptrace_blocked() {
    let output = Executor::run(
        Plan::new(["./payload"])
            .executable("payload", payload("ptrace_escape"))
            .binary_path("./payload")
            .timeout(Duration::from_secs(5)),
    )
    .expect("Executor should run");

    assert!(
        !output.success() || output.signal == Some(SIGSYS),
        "ptrace should be blocked. Exit: {:?}, Signal: {:?}",
        output.exit_code,
        output.signal
    );
}

// =============================================================================
// CVE-2019-10063: ioctl 64-bit argument bypass
// =============================================================================

/// Test that CVE-2019-10063 ioctl bypass is blocked.
///
/// CVE-2019-10063 exploits seccomp filters that check full 64-bit ioctl args.
/// By putting garbage in upper 32 bits, attackers bypass filters while kernel
/// processes only the lower 32 bits. Affected Flatpak < 1.0.8.
///
/// Reference: <https://github.com/flatpak/flatpak/security/advisories/GHSA-6qcp-mh39-cp53>
#[test]
#[ignore]
fn test_cve_2019_10063_ioctl_bypass_blocked() {
    let output = Executor::run(
        Plan::new(["./payload"])
            .executable("payload", payload("cve_2019_10063_ioctl_bypass"))
            .binary_path("./payload")
            .timeout(Duration::from_secs(5)),
    )
    .expect("Executor should run");

    // Should be blocked even with garbage in upper 32 bits
    assert!(
        !output.success() || output.signal == Some(SIGSYS),
        "CVE-2019-10063 ioctl bypass should be blocked. Exit: {:?}, Signal: {:?}",
        output.exit_code,
        output.signal
    );
}
