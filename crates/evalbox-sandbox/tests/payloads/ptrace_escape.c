// =============================================================================
// ptrace() - Process Debugging/Injection Attack
// =============================================================================
//
// WHY PTRACE IS DANGEROUS IN SANDBOXES:
//   ptrace() is the system call used for debugging. It allows one process to:
//   - Read/write another process's memory
//   - Inject code and modify registers
//   - Intercept and modify syscalls
//   - Effectively take complete control of another process
//
// SANDBOX ESCAPE VECTORS:
//   1. ptrace a process outside the sandbox (if PIDs are shared)
//   2. Inject code into a more privileged process
//   3. Bypass seccomp by ptracing a non-seccomp'd process
//   4. Debug the sandbox runtime itself
//
// CVE EXAMPLES:
//   - CVE-2019-13272: ptrace PTRACE_TRACEME allows privilege escalation
//   - CVE-2014-4699: ptrace RIP corruption vulnerability
//   - Many container escapes involve ptrace
//
// WHY BLOCK IT:
//   1. Allows arbitrary code injection into other processes
//   2. Can bypass security controls in traced process
//   3. No legitimate use case in sandboxed code execution
//   4. Kernel debugging interface = high privilege operation
//
// WHY THIS PAYLOAD:
//   This payload attempts to use ptrace. A secure sandbox must block ptrace
//   entirely to prevent process injection attacks.
//
// EXPECTED RESULT:
//   Sandbox should block ptrace() syscall via seccomp (SIGSYS).
//
// REFERENCES:
//   - CVE-2019-13272: https://nvd.nist.gov/vuln/detail/CVE-2019-13272
//   - https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html
//
// =============================================================================

#define _GNU_SOURCE
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <sys/wait.h>

int main(void) {
    // Try PTRACE_TRACEME first - trace ourselves
    // This is what debuggers use, and CVE-2019-13272 exploited this
    long ret = syscall(SYS_ptrace, 0 /* PTRACE_TRACEME */, 0, 0, 0);

    if (ret == 0) {
        // PTRACE_TRACEME succeeded - sandbox allows ptrace!
        return 0;
    }

    // Try PTRACE_ATTACH on our own PID (should also fail)
    ret = syscall(SYS_ptrace, 16 /* PTRACE_ATTACH */, getpid(), 0, 0);

    if (ret == 0) {
        // PTRACE_ATTACH succeeded - very dangerous
        syscall(SYS_ptrace, 17 /* PTRACE_DETACH */, getpid(), 0, 0);
        return 0;
    }

    // ptrace blocked - expected secure behavior
    // SIGSYS means seccomp killed us before we even returned
    return 1;
}
