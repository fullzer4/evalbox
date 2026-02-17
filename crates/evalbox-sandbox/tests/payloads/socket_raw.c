// =============================================================================
// SOCK_RAW Socket - Raw Packet Access Attack
// =============================================================================
//
// WHY SOCK_RAW IS DANGEROUS:
//   Raw sockets allow a process to craft and send arbitrary network packets,
//   bypassing the kernel's normal protocol processing. This gives direct
//   access to the network at the IP layer or below.
//
// ATTACK CAPABILITIES:
//   1. IP spoofing - Send packets with forged source addresses
//   2. Protocol attacks - Craft malformed packets to exploit vulnerabilities
//   3. Network scanning - Send ICMP, TCP SYN without normal restrictions
//   4. Sniffing - Capture all packets on the network interface
//   5. ARP spoofing - Redirect network traffic
//
// SECURITY IMPLICATIONS:
//   - Normally requires CAP_NET_RAW capability
//   - Docker blocks raw sockets by default
//   - Can be used to attack other containers on the same network
//   - Enables network-level exploits from within sandbox
//
// EXAMPLES OF RAW SOCKET MISUSE:
//   - Ping of Death attacks
//   - SYN flood attacks
//   - DNS amplification
//   - ICMP tunneling for data exfiltration
//
// WHY THIS PAYLOAD:
//   This payload attempts to create a SOCK_RAW socket. A secure sandbox
//   must block this socket type via seccomp filtering.
//
// EXPECTED RESULT:
//   Sandbox should kill the process with SIGSYS (signal 31) when
//   socket(AF_INET, SOCK_RAW, ...) is called.
//
// REFERENCES:
//   - https://man7.org/linux/man-pages/man7/raw.7.html
//   - Docker seccomp: blocks SOCK_RAW by default
//
// =============================================================================

#include <sys/socket.h>

#define AF_INET 2
#define SOCK_RAW 3
#define IPPROTO_ICMP 1

int main(void) {
    // Attempt to create a raw ICMP socket
    // This would allow sending arbitrary ICMP packets (ping, etc.)
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    if (fd >= 0) {
        // Raw socket created - sandbox is vulnerable!
        // Attacker could now craft arbitrary packets
        return 0;
    }

    // Should never reach here - seccomp should kill us first
    // If we do reach here, socket() failed (also acceptable)
    return 1;
}
