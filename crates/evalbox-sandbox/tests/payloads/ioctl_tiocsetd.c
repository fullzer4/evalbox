// =============================================================================
// TIOCSETD ioctl - TTY Line Discipline Attack
// =============================================================================
//
// VULNERABILITY:
//   TIOCSETD allows loading TTY line disciplines, which are kernel modules
//   that process terminal I/O. Multiple vulnerabilities have been found in
//   line disciplines over the years, making this ioctl a high-risk attack vector.
//
// HISTORICAL CVEs:
//   - CVE-2017-2636: Race condition in n_hdlc line discipline (double-free)
//   - CVE-2019-11815: Race condition in "slip" line discipline
//   - CVE-2020-14416: Race condition in tty->disc_data handling
//   - Multiple other line discipline vulnerabilities exist
//
// WHY IT'S DANGEROUS:
//   - Line disciplines run in kernel context
//   - Many line disciplines have complex state machines with race conditions
//   - Triggering a vulnerable line discipline = kernel code execution
//   - Even attempting to load disciplines can cause kernel issues
//
// ATTACK VECTOR:
//   1. Open a PTY or TTY device
//   2. Use TIOCSETD to load a vulnerable line discipline
//   3. Send specially crafted data to trigger the vulnerability
//   4. Achieve kernel code execution / privilege escalation
//
// WHY THIS PAYLOAD:
//   This payload tests if TIOCSETD ioctl is blocked. Line discipline attacks
//   have historically been a fruitful source of kernel exploits.
//
// EXPECTED RESULT:
//   Sandbox should block TIOCSETD via seccomp ioctl command filtering (SIGSYS).
//
// REFERENCES:
//   - https://madaidans-insecurities.github.io/guides/linux-hardening.html
//   - CVE-2017-2636: https://nvd.nist.gov/vuln/detail/CVE-2017-2636
//   - Linux kernel hardening guide recommends blocking TIOCSETD
//
// =============================================================================

#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

// TIOCSETD ioctl command - set line discipline
#define TIOCSETD 0x5423

// Some line discipline numbers
#define N_TTY    0   // Normal TTY
#define N_SLIP   1   // SLIP (Serial Line IP) - has had vulnerabilities
#define N_HDLC  13   // HDLC - CVE-2017-2636

int main(void) {
    // Try to open a PTY master
    int fd = open("/dev/ptmx", O_RDWR | O_NOCTTY);
    if (fd < 0) {
        // Try falling back to /dev/tty
        fd = open("/dev/tty", O_RDWR);
    }

    if (fd < 0) {
        // No TTY access - sandbox properly isolated
        return 1;
    }

    // Attempt to set line discipline to N_TTY (the safest one)
    // In a real attack, this would be a vulnerable discipline like N_HDLC
    int ldisc = N_TTY;
    int ret = ioctl(fd, TIOCSETD, &ldisc);

    close(fd);

    if (ret == 0) {
        // TIOCSETD succeeded - sandbox may be vulnerable to line discipline attacks
        return 0;
    }

    // TIOCSETD blocked (expected secure behavior)
    return 1;
}
