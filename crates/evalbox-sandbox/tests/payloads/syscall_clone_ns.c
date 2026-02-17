// =============================================================================
// clone(CLONE_NEWUSER) - User Namespace Creation Attack
// =============================================================================
//
// WHY USER NAMESPACES ARE DANGEROUS:
//   User namespaces allow an unprivileged process to gain "root" capabilities
//   inside the namespace. This fake root can then access kernel interfaces
//   that would normally require CAP_SYS_ADMIN.
//
// THE PROBLEM:
//   Many kernel vulnerabilities require elevated capabilities to exploit.
//   User namespaces provide those capabilities to any unprivileged user,
//   dramatically increasing the kernel attack surface.
//
// CVEs REQUIRING USER NAMESPACES:
//   - CVE-2024-1086: nf_tables exploit (needs netlink in userns)
//   - CVE-2022-0185: fsconfig exploit (needs CAP_SYS_ADMIN)
//   - CVE-2022-0492: cgroups escape (needs mount capability)
//   - CVE-2021-22555: Netfilter exploit
//   - CVE-2021-31440: eBPF verifier bypass
//   - Many, many more...
//
// WHAT CLONE_NEWUSER ENABLES:
//   1. Gain CAP_SYS_ADMIN inside namespace
//   2. Mount filesystems (cgroup, proc, sysfs)
//   3. Access nf_tables via netlink
//   4. Call fsopen/fsconfig
//   5. Exploit kernel bugs that need capabilities
//
// DISTRO RESPONSES:
//   - Ubuntu: Restricts userns via AppArmor
//   - Debian 11+: kernel.unprivileged_userns_clone=0
//   - RHEL/CentOS: Disabled by default
//   - Arch: user.max_user_namespaces=0
//
// WHY THIS PAYLOAD:
//   This payload tests that clone(CLONE_NEWUSER) is blocked. Blocking
//   user namespace creation prevents a large class of kernel exploits.
//
// EXPECTED RESULT:
//   Sandbox should kill the process with SIGSYS (signal 31) when
//   clone() is called with CLONE_NEWUSER flag.
//
// REFERENCES:
//   - https://lwn.net/Articles/673597/ (User namespace security concerns)
//   - https://man7.org/linux/man-pages/man7/user_namespaces.7.html
//   - kernel.unprivileged_userns_clone sysctl
//
// =============================================================================

#define _GNU_SOURCE
#include <sys/syscall.h>
#include <sched.h>
#include <unistd.h>

// Namespace creation flags (all should be blocked)
#define CLONE_NEWUSER  0x10000000  // New user namespace
#define CLONE_NEWNET   0x40000000  // New network namespace
#define CLONE_NEWNS    0x00020000  // New mount namespace
#define CLONE_NEWPID   0x20000000  // New PID namespace
#define CLONE_NEWIPC   0x08000000  // New IPC namespace
#define CLONE_NEWUTS   0x04000000  // New UTS namespace

int main(void) {
    // Attempt to create a new user namespace
    // This would give us "root" capabilities inside
    long ret = syscall(SYS_clone, CLONE_NEWUSER, 0, 0, 0, 0);

    if (ret == 0) {
        // Child in new namespace - we have fake root!
        // In a real exploit, we would now:
        // 1. Setup UID/GID mappings
        // 2. Use capabilities to access kernel interfaces
        // 3. Trigger a kernel vulnerability
        _exit(0);
    }

    if (ret > 0) {
        // Parent - child was created (VULNERABLE!)
        return 0;
    }

    // ret < 0: clone failed (expected - seccomp should kill us first)
    _exit(1);
}
