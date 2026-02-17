// =============================================================================
// User Namespace Creation - Common Escape Prerequisite
// =============================================================================
//
// WHY USER NAMESPACES ARE DANGEROUS IN SANDBOXES:
//   User namespaces allow an unprivileged process to gain "fake" root inside
//   the namespace. This is the prerequisite for many container/sandbox escapes
//   because it grants capabilities that can be used to exploit kernel bugs.
//
// CVEs REQUIRING USER NAMESPACES:
//   - CVE-2024-1086: nf_tables exploit (needs user namespace to access nf_tables)
//   - CVE-2022-0185: fsconfig exploit (needs CAP_SYS_ADMIN in user namespace)
//   - CVE-2022-0492: cgroups escape (needs user namespace to mount cgroupfs)
//   - CVE-2021-22555: Netfilter exploit (needs user namespace)
//   - Many other kernel exploits
//
// WHY BLOCK IT:
//   1. User namespaces increase kernel attack surface dramatically
//   2. "Root" inside namespace can access kernel interfaces normally restricted
//   3. Most kernel privilege escalation exploits require user namespaces
//   4. Major distros now restrict unprivileged user namespaces by default
//
// SYSCTL:
//   kernel.unprivileged_userns_clone=0 disables unprivileged user namespaces
//
// WHY THIS PAYLOAD:
//   This payload attempts to create a user namespace. A secure sandbox MUST
//   block this syscall to prevent a large class of kernel exploits.
//
// EXPECTED RESULT:
//   Sandbox should block clone(CLONE_NEWUSER) via seccomp (SIGSYS).
//
// REFERENCES:
//   - https://lwn.net/Articles/673597/ (User namespace security concerns)
//   - https://www.openwall.com/lists/oss-security/2021/07/07/1 (Discussion)
//
// =============================================================================

#define _GNU_SOURCE
#include <sys/syscall.h>
#include <sched.h>
#include <unistd.h>
#include <sys/wait.h>

#define CLONE_NEWUSER 0x10000000

int main(void) {
    // Attempt to create a new user namespace
    // This gives "root" capabilities inside the namespace
    int ret = syscall(SYS_clone, CLONE_NEWUSER, 0, 0, 0, 0);

    if (ret < 0) {
        // User namespace creation blocked - GOOD!
        // Either seccomp blocked it, or sysctl disabled it
        return 1;
    }

    if (ret == 0) {
        // Child: we're "root" inside the user namespace now
        // In a real exploit, we would now:
        // 1. Setup UID/GID mappings
        // 2. Use our "root" caps to access privileged kernel interfaces
        // 3. Exploit a kernel vulnerability (nf_tables, fsconfig, etc.)

        // Check if we have root capabilities
        if (geteuid() == 0 || getuid() == 0) {
            // We have "root" - namespace creation worked
            _exit(0);
        }
        _exit(1);
    }

    // Parent: check if child got "root"
    int status;
    waitpid(ret, &status, 0);

    // Return child's exit status
    // 0 = namespace created successfully (VULNERABLE)
    // 1 = namespace creation failed (SECURE)
    return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}
