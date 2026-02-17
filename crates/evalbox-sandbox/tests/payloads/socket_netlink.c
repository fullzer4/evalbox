// =============================================================================
// AF_NETLINK Socket - Kernel Interface Access Attack
// =============================================================================
//
// WHAT IS NETLINK:
//   Netlink is a Linux-specific socket family for communication between
//   userspace and the kernel. It provides access to many kernel subsystems
//   including networking, routing, firewall rules, and more.
//
// WHY AF_NETLINK IS DANGEROUS:
//   1. Direct interface to kernel subsystems
//   2. Many netlink handlers have had vulnerabilities
//   3. Access to nf_tables (CVE-2024-1086)
//   4. Can modify network configuration
//   5. Enables kernel exploitation from userspace
//
// NETLINK PROTOCOLS:
//   - NETLINK_ROUTE (0): Routing tables, interfaces
//   - NETLINK_FIREWALL (3): Deprecated firewall interface
//   - NETLINK_NETFILTER (12): nf_tables, iptables - VERY DANGEROUS
//   - NETLINK_KOBJECT_UEVENT (15): Device events
//   - NETLINK_AUDIT (9): Audit system
//
// CVEs USING NETLINK:
//   - CVE-2024-1086: nf_tables use-after-free via NETLINK_NETFILTER
//   - CVE-2021-22555: Netfilter heap out-of-bounds write
//   - CVE-2017-8890: Double free in net/ipv4/inet_connection_sock.c
//   - Many other kernel networking vulnerabilities
//
// WHY BLOCK IT:
//   1. No legitimate use for netlink in sandboxed code execution
//   2. Major attack surface for kernel exploits
//   3. Docker blocks AF_NETLINK by default
//   4. Even "safe" netlink operations can leak information
//
// WHY THIS PAYLOAD:
//   This payload attempts to create an AF_NETLINK socket with
//   NETLINK_NETFILTER protocol - the exact attack vector for
//   CVE-2024-1086 and other nf_tables exploits.
//
// EXPECTED RESULT:
//   Sandbox should kill the process with SIGSYS (signal 31) when
//   socket(AF_NETLINK, ...) is called.
//
// REFERENCES:
//   - https://man7.org/linux/man-pages/man7/netlink.7.html
//   - CVE-2024-1086: https://github.com/Notselwyn/CVE-2024-1086
//   - https://www.sysdig.com/blog/detecting-cve-2024-1086
//
// =============================================================================

#include <sys/socket.h>

#define AF_NETLINK 16
#define SOCK_RAW 3
#define NETLINK_NETFILTER 12  // Access to nf_tables - CVE-2024-1086

int main(void) {
    // Attempt to create netlink socket for nf_tables access
    // This is the EXACT entry point for CVE-2024-1086 exploitation
    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER);

    if (fd >= 0) {
        // Netlink socket created - sandbox is vulnerable!
        // Attacker could now communicate with nf_tables subsystem
        // and exploit CVE-2024-1086 or similar vulnerabilities
        return 0;
    }

    // Should never reach here - seccomp should kill us first
    return 1;
}
