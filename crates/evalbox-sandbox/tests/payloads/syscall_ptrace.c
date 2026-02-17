// =============================================================================
// ptrace() syscall - Process Debugging/Tracing Attack
// =============================================================================
//
// WHY PTRACE IS DANGEROUS:
//   ptrace() is the Unix debugging interface. It allows one process to:
//   1. Read and write another process's memory
//   2. Read and modify CPU registers
//   3. Intercept and modify system calls
//   4. Single-step through code execution
//   5. Inject code into a running process
//
// SANDBOX ESCAPE VECTORS:
//   1. Attach to a process outside the sandbox (if PIDs visible)
//   2. Inject shellcode into a privileged process
//   3. Modify a traced process to bypass its security checks
//   4. Read secrets from other processes' memory
//   5. Bypass seccomp in traced process (pre-4.8 kernels)
//
// CVEs INVOLVING PTRACE:
//   - CVE-2019-13272: PTRACE_TRACEME allows privilege escalation
//   - CVE-2014-4699: ptrace RIP corruption vulnerability
//   - Many container escapes involve ptrace
//
// PTRACE OPERATIONS:
//   - PTRACE_TRACEME (0): Allow parent to trace this process
//   - PTRACE_ATTACH (16): Attach to a running process
//   - PTRACE_PEEKDATA: Read process memory
//   - PTRACE_POKEDATA: Write process memory
//
// WHY BLOCK IT:
//   1. No legitimate use for debugging in sandboxed code execution
//   2. Enables arbitrary code injection
//   3. Can bypass security controls in traced process
//   4. High-privilege kernel interface
//
// WHY THIS PAYLOAD:
//   This payload attempts to use ptrace. A secure sandbox must block
//   this syscall entirely via seccomp.
//
// EXPECTED RESULT:
//   Sandbox should kill the process with SIGSYS (signal 31).
//
// REFERENCES:
//   - https://man7.org/linux/man-pages/man2/ptrace.2.html
//   - CVE-2019-13272: https://nvd.nist.gov/vuln/detail/CVE-2019-13272
//   - Yama LSM: https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html
//
// =============================================================================

#define _GNU_SOURCE
#include <sys/syscall.h>
#include <unistd.h>

// ptrace requests
#define PTRACE_TRACEME 0

int main(void) {
    // Attempt PTRACE_TRACEME - allow parent to trace us
    // This is what debuggers use, and what CVE-2019-13272 exploited
    long ret = syscall(SYS_ptrace, PTRACE_TRACEME, 0, 0, 0);

    if (ret == 0) {
        // ptrace succeeded - sandbox allows debugging!
        return 0;
    }

    // Should never reach here - seccomp should kill us
    _exit(1);
}
