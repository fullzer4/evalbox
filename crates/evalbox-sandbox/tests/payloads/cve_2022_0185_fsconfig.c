// =============================================================================
// CVE-2022-0185: Linux Kernel legacy_parse_param Heap Buffer Overflow
// =============================================================================
//
// VULNERABILITY:
//   A heap-based buffer overflow in the Linux kernel's "legacy_parse_param"
//   function of filesystem context functionality. Sending 4095+ bytes to
//   this function provides a write primitive that can corrupt kernel memory.
//
// IMPACT:
//   - Local privilege escalation to root
//   - Container escape in Kubernetes environments
//   - Bypass of Linux namespace restrictions
//
// AFFECTED VERSIONS:
//   Linux kernel 5.1-rc1 through 5.16.2
//   (5.4.173, 5.10.93, 5.15.16, 5.16.2 contain fixes)
//
// ATTACK VECTOR:
//   Uses fsconfig() syscall with FSCONFIG_SET_STRING to overflow the buffer.
//   Requires CAP_SYS_ADMIN in user namespace to call fsopen()/fsconfig().
//
// WHY THIS PAYLOAD:
//   This payload attempts to use fsconfig() syscall which is the attack vector
//   for CVE-2022-0185. If the sandbox allows this syscall and user namespaces,
//   it may be vulnerable.
//
// EXPECTED RESULT:
//   Sandbox should either:
//   1. Block fsconfig() syscall via seccomp (SIGSYS)
//   2. Block user namespace creation (SIGSYS on clone(CLONE_NEWUSER))
//
// REFERENCES:
//   - https://www.crowdstrike.com/blog/cve-2022-0185-kubernetes-container-escape
//   - https://www.willsroot.io/2022/01/cve-2022-0185.html
//   - https://nvd.nist.gov/vuln/detail/CVE-2022-0185
//
// =============================================================================

#define _GNU_SOURCE
#include <sys/syscall.h>
#include <unistd.h>
#include <errno.h>

// fsconfig syscall number (not in older libc)
#ifndef SYS_fsconfig
#define SYS_fsconfig 431
#endif

#ifndef SYS_fsopen
#define SYS_fsopen 430
#endif

// fsconfig commands
#define FSCONFIG_SET_STRING 1

int main(void) {
    // Step 1: Try to open a filesystem context
    // This requires CAP_SYS_ADMIN or user namespace
    int fs_fd = syscall(SYS_fsopen, "ext4", 0);

    if (fs_fd < 0) {
        // fsopen failed - likely no permission or syscall blocked
        // This is the expected secure behavior
        return 1;
    }

    // Step 2: Attempt to trigger the vulnerable code path
    // In a real exploit, this would send 4095+ bytes to overflow
    char payload[16] = "test";
    int ret = syscall(SYS_fsconfig, fs_fd, FSCONFIG_SET_STRING, "source", payload, 0);

    close(fs_fd);

    // If we got here, fsconfig is accessible - potential vulnerability
    return (ret == 0) ? 0 : 1;
}
