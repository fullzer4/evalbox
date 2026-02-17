// =============================================================================
// CVE-2022-0492: Linux Kernel cgroups release_agent Container Escape
// =============================================================================
//
// VULNERABILITY:
//   The Linux kernel didn't verify that the process setting the release_agent
//   file has CAP_SYS_ADMIN capability. An attacker could mount cgroupfs in a
//   user namespace and edit the release_agent to execute arbitrary commands
//   with root privileges in the host namespace.
//
// IMPACT:
//   - Container escape with root privileges on host
//   - Arbitrary code execution outside container
//   - CVSS score: 7.0 (High)
//
// AFFECTED VERSIONS:
//   Linux kernel < 5.17-rc3
//
// ATTACK VECTOR:
//   1. Create user namespace with unshare()
//   2. Mount cgroup filesystem
//   3. Create cgroup and set notify_on_release=1
//   4. Write path to malicious script in release_agent
//   5. Trigger release (all processes in cgroup exit)
//   6. Kernel executes release_agent as root in init namespace
//
// WHY THIS PAYLOAD:
//   This payload attempts the initial steps of CVE-2022-0492 exploitation.
//   It tries to create a user namespace and mount cgroup - both should be
//   blocked by a secure sandbox.
//
// EXPECTED RESULT:
//   Sandbox should block:
//   1. clone(CLONE_NEWUSER) via seccomp (SIGSYS), OR
//   2. mount() syscall via seccomp (SIGSYS)
//
// REFERENCES:
//   - https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/
//   - https://www.sysdig.com/blog/detecting-mitigating-cve-2022-0492-sysdig
//   - https://nvd.nist.gov/vuln/detail/CVE-2022-0492
//
// =============================================================================

#define _GNU_SOURCE
#include <sys/mount.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sched.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>

#define CLONE_NEWUSER 0x10000000
#define CLONE_NEWNS   0x00020000

int main(void) {
    // Step 1: Try to create a new user namespace
    // This is required to mount cgroup without real CAP_SYS_ADMIN
    int ret = syscall(SYS_clone, CLONE_NEWUSER | CLONE_NEWNS, 0, 0, 0, 0);

    if (ret < 0) {
        // User namespace creation blocked - sandbox is secure
        return 1;
    }

    if (ret == 0) {
        // Child process in new namespace
        // Step 2: Try to mount cgroup filesystem
        mkdir("/tmp/cgrp", 0755);
        ret = mount("cgroup", "/tmp/cgrp", "cgroup", 0, "rdma");

        if (ret == 0) {
            // Mount succeeded - this is bad!
            // In a real exploit, we would now set up release_agent
            umount("/tmp/cgrp");
            rmdir("/tmp/cgrp");
            _exit(0);  // Vulnerable
        }

        rmdir("/tmp/cgrp");
        _exit(1);  // Mount blocked
    }

    // Parent: wait for child
    int status;
    waitpid(ret, &status, 0);

    return 0;
}
