// =============================================================================
// CVE-2024-1086: Linux Kernel nf_tables Use-After-Free
// =============================================================================
//
// VULNERABILITY:
//   A use-after-free vulnerability in Linux kernel's netfilter nf_tables
//   component. The nft_verdict_init() function allows positive values as
//   drop error within the hook verdict, causing a double-free when NF_DROP
//   is issued with a drop error resembling NF_ACCEPT.
//
// IMPACT:
//   - Local privilege escalation to root
//   - Container/sandbox escape
//   - Active exploitation in ransomware campaigns (confirmed by CISA Oct 2025)
//
// AFFECTED VERSIONS:
//   Linux kernel v5.14 to v6.6 (patched in v5.15.149+, v6.1.76+, v6.6.15+)
//
// ATTACK VECTOR:
//   Requires access to AF_NETLINK socket with NETLINK_NETFILTER protocol
//   to interact with nf_tables subsystem.
//
// WHY THIS PAYLOAD:
//   This payload attempts to create an AF_NETLINK socket with NETLINK_NETFILTER,
//   which is the first step in exploiting CVE-2024-1086. If the sandbox allows
//   this socket type, it's potentially vulnerable to this attack.
//
// EXPECTED RESULT:
//   Sandbox should block AF_NETLINK sockets via seccomp, causing SIGSYS.
//
// REFERENCES:
//   - https://www.sysdig.com/blog/detecting-cve-2024-1086
//   - https://github.com/Notselwyn/CVE-2024-1086
//   - https://nvd.nist.gov/vuln/detail/CVE-2024-1086
//
// =============================================================================

#include <sys/socket.h>
#include <unistd.h>

#define AF_NETLINK 16
#define NETLINK_NETFILTER 12

int main(void) {
    // Attempt to create netlink socket for nf_tables access
    // This is the entry point for CVE-2024-1086 exploitation
    int fd = socket(AF_NETLINK, 3 /* SOCK_RAW */, NETLINK_NETFILTER);

    if (fd >= 0) {
        // Socket created - sandbox is potentially vulnerable!
        close(fd);
        return 0;
    }

    // Socket creation failed (expected if properly sandboxed)
    return 1;
}
