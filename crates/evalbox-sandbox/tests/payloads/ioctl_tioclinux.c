// =============================================================================
// TIOCLINUX ioctl - Virtual Console Input Injection
// =============================================================================
//
// VULNERABILITY:
//   TIOCLINUX is a Linux-specific ioctl that provides various virtual console
//   operations. Subcommand 2 allows setting the selection, and when combined
//   with subcommand 3 (paste), can inject input into the console.
//
// WHY IT'S DANGEROUS:
//   - Can inject arbitrary text into virtual consoles
//   - Works on /dev/tty, /dev/console, /dev/ttyN
//   - Has been used in sandbox escape attacks
//   - Similar attack vector to TIOCSTI but for virtual consoles
//
// RELATED VULNERABILITIES:
//   - Often used in conjunction with CVE-2017-5226 style attacks
//   - Part of the "dangerous ioctls" category along with TIOCSTI, TIOCSETD
//
// ATTACK VECTOR:
//   1. Open a virtual console device
//   2. Use TIOCLINUX subcommand 2 to set selection
//   3. Use TIOCLINUX subcommand 3 to paste (inject) the selection
//   4. Injected text executes as commands in the console
//
// WHY THIS PAYLOAD:
//   This payload tests if TIOCLINUX ioctl is blocked. A secure sandbox
//   should block dangerous ioctls via seccomp argument filtering.
//
// EXPECTED RESULT:
//   Sandbox should block TIOCLINUX via seccomp ioctl command filtering (SIGSYS).
//
// REFERENCES:
//   - https://madaidans-insecurities.github.io/guides/linux-hardening.html
//   - Linux kernel source: drivers/tty/vt/vt.c (tioclinux function)
//
// =============================================================================

#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>

// TIOCLINUX ioctl command
#define TIOCLINUX 0x541C

int main(void) {
    // Try to open the console
    int fd = open("/dev/tty", O_RDWR);
    if (fd < 0) {
        fd = open("/dev/console", O_RDWR);
    }

    if (fd < 0) {
        // No console access - sandbox properly isolated
        return 1;
    }

    // TIOCLINUX with subfunction 10 (get shift state) - least invasive test
    // Real attacks would use subfunctions 2/3 for selection/paste
    char arg = 10;
    int ret = ioctl(fd, TIOCLINUX, &arg);

    close(fd);

    if (ret == 0) {
        // TIOCLINUX succeeded - sandbox may be vulnerable
        return 0;
    }

    // TIOCLINUX blocked (expected secure behavior)
    return 1;
}
