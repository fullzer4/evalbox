// =============================================================================
// mount() syscall - Filesystem Manipulation Attack
// =============================================================================
//
// WHY MOUNT IS DANGEROUS IN SANDBOXES:
//   The mount() syscall allows attaching filesystems to the directory tree.
//   In a sandbox context, this can be used to:
//   - Overlay sensitive files with attacker-controlled content
//   - Access devices that should be restricted
//   - Escape chroot/pivot_root by mounting the real root
//   - Mount procfs/sysfs to gain kernel information
//
// CVEs INVOLVING MOUNT:
//   - CVE-2022-0492: Mount cgroupfs to escape via release_agent
//   - CVE-2022-0185: Requires mount capability in user namespace
//   - Various Docker/container escapes using privileged mounts
//
// ATTACK VECTORS:
//   1. mount("none", "/tmp", "tmpfs", 0, NULL) - Create arbitrary tmpfs
//   2. mount("/dev/sda1", "/mnt", "ext4", 0, NULL) - Access host disks
//   3. mount("proc", "/proc", "proc", 0, NULL) - Access kernel info
//   4. mount("overlay", "/", "overlay", 0, opts) - Overlay root filesystem
//
// WHY BLOCK IT:
//   1. No legitimate use case for mounting in sandboxed code execution
//   2. Even with user namespaces, mount can be dangerous
//   3. Enables many container escape techniques
//   4. Bypasses filesystem isolation (Landlock)
//
// WHY THIS PAYLOAD:
//   This payload attempts to call mount(). A secure sandbox must block
//   this syscall entirely via seccomp.
//
// EXPECTED RESULT:
//   Sandbox should kill the process with SIGSYS (signal 31) when
//   mount() is attempted, as it's not in the syscall whitelist.
//
// REFERENCES:
//   - https://man7.org/linux/man-pages/man2/mount.2.html
//   - https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/
//
// =============================================================================

#define _GNU_SOURCE
#include <sys/syscall.h>
#include <unistd.h>

int main(void) {
    // Attempt to mount a tmpfs - should trigger SIGSYS immediately
    // Parameters: source, target, fstype, flags, data
    long ret = syscall(SYS_mount, "none", "/tmp", "tmpfs", 0, NULL);

    // If we reach here, mount() was allowed (VERY BAD)
    // In a real exploit, we would now have arbitrary filesystem control
    if (ret == 0) {
        // Mount succeeded - sandbox is vulnerable!
        syscall(SYS_umount2, "/tmp", 0);
        return 0;
    }

    // Mount failed (expected if syscall is blocked or lacks CAP_SYS_ADMIN)
    // Note: SIGSYS means we never even return here
    return 1;
}
