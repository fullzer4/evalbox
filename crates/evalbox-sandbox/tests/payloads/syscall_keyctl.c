// =============================================================================
// keyctl() syscall - Kernel Keyring Manipulation
// =============================================================================
//
// WHY KEYCTL IS DANGEROUS IN SANDBOXES:
//   The Linux kernel keyring is a shared facility that stores authentication
//   tokens, encryption keys, and other sensitive data. The keyring is NOT
//   namespaced (in most kernel versions), meaning a sandboxed process could
//   potentially access keys from the host or other containers.
//
// SECURITY ISSUES:
//   1. Keyrings are not fully isolated by namespaces (kernel < 5.2)
//   2. Process can read/write keys in session keyring
//   3. Potential to leak cryptographic secrets
//   4. Container escapes via keyring manipulation
//
// CVEs AND EXPLOITS:
//   - CVE-2016-0728: Use-after-free in kernel keyring (privilege escalation)
//   - CVE-2017-17449: netlink_dump kernel keyring info leak
//   - Various container escapes using keyctl
//
// ATTACK VECTORS:
//   1. KEYCTL_GET_KEYRING_ID: Enumerate keyrings
//   2. KEYCTL_READ: Read key contents
//   3. KEYCTL_LINK: Link keys to accessible keyrings
//   4. KEYCTL_JOIN_SESSION_KEYRING: Join another session's keyring
//
// WHY BLOCK IT:
//   1. No legitimate use case for keyring access in sandboxed code
//   2. Keyrings not properly namespaced in older kernels
//   3. Defense in depth against kernel keyring exploits
//   4. Docker also blocks keyctl by default
//
// WHY THIS PAYLOAD:
//   This payload attempts to access the kernel keyring. A secure sandbox
//   must block keyctl() to prevent keyring-based attacks.
//
// EXPECTED RESULT:
//   Sandbox should kill the process with SIGSYS (signal 31).
//
// REFERENCES:
//   - https://man7.org/linux/man-pages/man2/keyctl.2.html
//   - https://nvd.nist.gov/vuln/detail/CVE-2016-0728
//   - Docker: "Prevent containers from using the kernel keyring"
//
// =============================================================================

#define _GNU_SOURCE
#include <sys/syscall.h>
#include <unistd.h>

// keyctl operations
#define KEYCTL_GET_KEYRING_ID 0

// Special keyring IDs
#define KEY_SPEC_SESSION_KEYRING -3

int main(void) {
    // Attempt to get the session keyring ID
    // This is a relatively benign operation, but keyctl should be blocked entirely
    long ret = syscall(SYS_keyctl,
                       KEYCTL_GET_KEYRING_ID,
                       KEY_SPEC_SESSION_KEYRING,
                       0);

    // If we reach here, keyctl was allowed
    if (ret >= 0) {
        // Got keyring ID - sandbox allows keyctl!
        return 0;
    }

    // Failed (expected - either SIGSYS or ENOSYS)
    return 1;
}
