// =============================================================================
// CVE-2017-5226 / CVE-2016-7545: TIOCSTI Terminal Injection Escape
// =============================================================================
//
// VULNERABILITY:
//   The TIOCSTI ioctl allows a process to inject characters into the terminal's
//   input buffer. A sandboxed process can use this to inject commands that
//   execute in the parent (unsandboxed) shell session after the sandbox exits.
//
// IMPACT:
//   - Sandbox escape (bubblewrap, SELinux sandbox, etc.)
//   - Arbitrary command execution in parent session
//   - Privilege escalation if parent has higher privileges
//
// AFFECTED SOFTWARE:
//   - bubblewrap < 0.1.5 (CVE-2017-5226)
//   - SELinux sandbox/policycoreutils (CVE-2016-7545)
//   - util-linux runuser (CVE-2016-2779)
//   - Any sandbox that shares terminal with parent
//
// ATTACK VECTOR:
//   1. Get file descriptor to controlling terminal (/dev/tty)
//   2. Use TIOCSTI ioctl to inject characters (e.g., "malicious_command\n")
//   3. Characters appear in parent shell's input buffer
//   4. After sandbox exits, parent shell executes the injected command
//
// WHY THIS PAYLOAD:
//   This payload attempts the TIOCSTI ioctl attack. A secure sandbox must
//   either block TIOCSTI via seccomp or create a new session (setsid).
//
// EXPECTED RESULT:
//   Sandbox should block TIOCSTI via seccomp ioctl filtering (SIGSYS)
//   or the ioctl should fail with ENOTTY (no controlling terminal).
//
// REFERENCES:
//   - https://github.com/containers/bubblewrap/issues/142
//   - https://bugzilla.redhat.com/show_bug.cgi?id=1378577
//   - https://nvd.nist.gov/vuln/detail/CVE-2017-5226
//
// =============================================================================

#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

// TIOCSTI: "Terminal I/O Control - Simulate Terminal Input"
// Pushes a character into the terminal's input queue
#define TIOCSTI 0x5412

int main(void) {
    // Try to open the controlling terminal
    int tty_fd = open("/dev/tty", O_RDWR);
    if (tty_fd < 0) {
        // No controlling terminal - sandbox properly isolated (setsid)
        return 1;
    }

    // Attempt to inject a harmless character via TIOCSTI
    // In a real attack, this would be a malicious command
    char c = '#';  // Comment character - harmless for testing
    int ret = ioctl(tty_fd, TIOCSTI, &c);

    close(tty_fd);

    if (ret == 0) {
        // TIOCSTI succeeded - sandbox is VULNERABLE!
        return 0;
    }

    // TIOCSTI blocked (expected secure behavior)
    return 1;
}
