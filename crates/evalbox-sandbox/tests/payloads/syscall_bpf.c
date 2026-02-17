// =============================================================================
// bpf() syscall - eBPF Program Loading
// =============================================================================
//
// WHY BPF IS DANGEROUS IN SANDBOXES:
//   The bpf() syscall allows loading and manipulating eBPF programs that run
//   inside the kernel. eBPF has been a major source of kernel vulnerabilities
//   and privilege escalation exploits in recent years.
//
// SECURITY CONCERNS:
//   1. eBPF runs in kernel context with elevated privileges
//   2. JIT compiler bugs can lead to arbitrary code execution
//   3. Verifier bypasses have led to many CVEs
//   4. Can read/write arbitrary kernel memory if exploited
//   5. Unprivileged eBPF has been a major attack surface
//
// CVEs AND EXPLOITS:
//   - CVE-2021-3490: eBPF ALU32 bounds tracking bug (privilege escalation)
//   - CVE-2021-31440: eBPF verifier bypass
//   - CVE-2022-23222: eBPF verifier pointer arithmetic
//   - CVE-2023-2163: eBPF verifier state pruning bug
//   - Many more eBPF-related CVEs
//
// ATTACK VECTORS:
//   1. BPF_PROG_LOAD: Load malicious eBPF program
//   2. Exploit verifier bugs to bypass safety checks
//   3. Use maps to read/write kernel memory
//   4. Escape from containers via kernel compromise
//
// WHY BLOCK IT:
//   1. No legitimate use case for eBPF in sandboxed code execution
//   2. eBPF is a massive kernel attack surface
//   3. Even "safe" eBPF programs can have unintended effects
//   4. Docker blocks bpf by default
//   5. Many distros disable unprivileged eBPF entirely
//
// KERNEL SYSCTLS:
//   kernel.unprivileged_bpf_disabled=1 (recommended on all systems)
//
// WHY THIS PAYLOAD:
//   This payload attempts to use bpf(). A secure sandbox must block
//   this syscall to prevent eBPF-based kernel exploits.
//
// EXPECTED RESULT:
//   Sandbox should kill the process with SIGSYS (signal 31).
//
// REFERENCES:
//   - https://man7.org/linux/man-pages/man2/bpf.2.html
//   - https://lwn.net/Articles/853489/ (eBPF attack surface)
//   - https://ciq.com/blog/linux-kernel-cves-2025 (eBPF CVE trends)
//
// =============================================================================

#define _GNU_SOURCE
#include <sys/syscall.h>
#include <unistd.h>
#include <string.h>

// BPF commands
#define BPF_MAP_CREATE 0
#define BPF_PROG_LOAD  5

// BPF map types
#define BPF_MAP_TYPE_ARRAY 2

// Minimal bpf_attr structure for map creation
struct bpf_create_map_attr {
    unsigned int map_type;
    unsigned int key_size;
    unsigned int value_size;
    unsigned int max_entries;
};

int main(void) {
    // Attempt to create a simple BPF map
    // This is a relatively benign BPF operation, but bpf should be blocked entirely
    struct bpf_create_map_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_type = BPF_MAP_TYPE_ARRAY;
    attr.key_size = 4;
    attr.value_size = 4;
    attr.max_entries = 1;

    long ret = syscall(SYS_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));

    if (ret >= 0) {
        // BPF map created - sandbox allows bpf!
        close(ret);
        return 0;
    }

    // Failed (expected - either SIGSYS, EPERM, or ENOSYS)
    return 1;
}
