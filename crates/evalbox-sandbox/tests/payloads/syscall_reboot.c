// =============================================================================
// reboot() syscall - System Reboot/Halt Attack
// =============================================================================
//
// WHY REBOOT IS DANGEROUS:
//   The reboot() syscall can halt, reboot, or suspend the entire system.
//   Even though it normally requires CAP_SYS_BOOT, a sandbox that doesn't
//   block it at the seccomp level could be vulnerable if capabilities
//   are misconfigured.
//
// POSSIBLE ACTIONS:
//   - LINUX_REBOOT_CMD_RESTART: Reboot the system
//   - LINUX_REBOOT_CMD_HALT: Halt the system
//   - LINUX_REBOOT_CMD_POWER_OFF: Power off the system
//   - LINUX_REBOOT_CMD_CAD_ON: Enable Ctrl-Alt-Del
//   - LINUX_REBOOT_CMD_KEXEC: Execute new kernel
//
// ATTACK SCENARIO:
//   1. Sandbox with capability leak or user namespace root
//   2. Attacker calls reboot() with LINUX_REBOOT_CMD_HALT
//   3. Entire host system halts - denial of service
//
// WHY BLOCK IT:
//   1. No legitimate use case for rebooting from sandboxed code
//   2. Potential DoS if capabilities are misconfigured
//   3. Defense in depth - don't rely solely on capabilities
//   4. Easy to block with no compatibility impact
//
// WHY THIS PAYLOAD:
//   This payload attempts to call reboot(). A secure sandbox must
//   block this syscall entirely via seccomp as defense in depth.
//
// EXPECTED RESULT:
//   Sandbox should kill the process with SIGSYS (signal 31) when
//   reboot() is attempted, as it's not in the syscall whitelist.
//
// REFERENCES:
//   - https://man7.org/linux/man-pages/man2/reboot.2.html
//   - Docker blocks reboot: https://docs.docker.com/engine/security/seccomp/
//
// =============================================================================

#define _GNU_SOURCE
#include <sys/syscall.h>
#include <unistd.h>

// Magic values required by reboot()
#define LINUX_REBOOT_MAGIC1  0xfee1dead
#define LINUX_REBOOT_MAGIC2  672274793
#define LINUX_REBOOT_CMD_CAD_ON  0x89ABCDEF  // Least destructive option

int main(void) {
    // Attempt reboot with least destructive command (enable Ctrl-Alt-Del)
    // Even this should be blocked - we don't want ANY reboot syscalls
    long ret = syscall(SYS_reboot,
                       LINUX_REBOOT_MAGIC1,
                       LINUX_REBOOT_MAGIC2,
                       LINUX_REBOOT_CMD_CAD_ON,
                       NULL);

    // If we reach here without SIGSYS, the syscall was allowed
    // (Though it likely failed due to CAP_SYS_BOOT requirement)
    if (ret == 0) {
        // Reboot command accepted - very dangerous!
        return 0;
    }

    // Failed (expected - either SIGSYS or EPERM)
    return 1;
}
