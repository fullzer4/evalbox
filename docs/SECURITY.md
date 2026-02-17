# evalbox Security Model

## Defense in Depth

evalbox uses **7 independent isolation layers**. Each layer provides protection even if another layer is bypassed.

```
┌─────────────────────────────────────────────────────────────┐
│  Layer 1  │         User Namespaces          │  Identity    │
├───────────┼──────────────────────────────────┼──────────────┤
│  Layer 2  │          PID Namespace           │  Process     │
├───────────┼──────────────────────────────────┼──────────────┤
│  Layer 3  │        Network Namespace         │  Network     │
├───────────┼──────────────────────────────────┼──────────────┤
│  Layer 4  │   Mount Namespace + pivot_root   │  Filesystem  │
├───────────┼──────────────────────────────────┼──────────────┤
│  Layer 5  │          Landlock LSM            │  FS Rules    │
├───────────┼──────────────────────────────────┼──────────────┤
│  Layer 6  │          Seccomp BPF             │  Syscalls    │
├───────────┼──────────────────────────────────┼──────────────┤
│  Layer 7  │           rlimits                │  Resources   │
└───────────┴──────────────────────────────────┴──────────────┘
```

---

## Isolation Layers

### Layer 1: User Namespaces

User namespaces provide identity isolation.

| Inside Sandbox | Outside Sandbox |
|----------------|-----------------|
| UID 0 (root) | Real user UID |
| GID 0 (root) | Real user GID |
| Full capabilities | No capabilities |

**Security properties:**
- Cannot access host user's files (different UID)
- Capabilities only valid inside namespace
- Cannot escalate to real root

### Layer 2: PID Namespace

Process isolation prevents interference with host processes.

```
Host PID Namespace          Sandbox PID Namespace
┌───────────────────┐      ┌───────────────────┐
│  PID 1 (init)     │      │  PID 1 (sandbox)  │
│  PID 1234 (shell) │      │  PID 2 (python)   │
│  PID 5678 (...)   │      │  PID 3 (child)    │
└───────────────────┘      └───────────────────┘
         │                          │
         │    ✗ Cannot see          │
         │◄─────────────────────────┤
         │    ✗ Cannot signal       │
```

**Security properties:**
- Sandbox sees only its own processes
- Cannot enumerate host processes
- Cannot send signals to host processes
- kill() safe inside namespace

### Layer 3: Network Namespace

Network isolation blocks all network access by default.

```
┌─────────────────────────────────────────┐
│           Host Network                   │
│  eth0: 192.168.1.100                    │
│  lo: 127.0.0.1                          │
│  docker0: 172.17.0.1                    │
└─────────────────────────────────────────┘
              ✗ No access
┌─────────────────────────────────────────┐
│         Sandbox Network                  │
│  (empty - no interfaces)                │
│                                         │
│  • No loopback                          │
│  • No external access                   │
│  • socket() works but connect() fails  │
└─────────────────────────────────────────┘
```

**Security properties:**
- Cannot connect to localhost services
- Cannot access local network
- Cannot exfiltrate data via network
- Optional: Enable with `.network(true)`

### Layer 4: Mount Namespace + pivot_root

Filesystem isolation provides a minimal, controlled view.

```
Host Filesystem              Sandbox Filesystem
/                            /
├── home/                    ├── work/        ← User workspace (rw)
│   └── user/ ✗              ├── tmp/         ← Temp files (rw)
├── etc/                     ├── etc/         ← Minimal config
│   └── shadow ✗             │   ├── passwd   (nobody)
├── root/ ✗                  │   └── hosts    (localhost)
├── proc/ ✗                  ├── dev/         ← Minimal devices
├── sys/ ✗                   │   ├── null
├── usr/  ───────────────────┼── usr/         ← Bind mount (ro)
├── lib/  ───────────────────┼── lib/         ← Bind mount (ro)
└── lib64/ ──────────────────┼── lib64/       ← Bind mount (ro)
                             └── (host root unmounted)
```

**Security properties:**
- Cannot access /home, /root
- Cannot read /etc/shadow, /etc/passwd (host)
- Cannot access /proc (no process info)
- Cannot access /sys (no kernel info)
- Host filesystem completely unmounted

### Layer 5: Landlock LSM

Kernel-enforced filesystem access control (requires Linux 5.13+).

```rust
// Landlock ruleset
Ruleset {
    read_only: ["/usr", "/lib", "/lib64", "/bin", "/etc"],
    read_write: ["/work", "/tmp"],
    execute: ["/usr/bin", "/bin"],
    no_access: [everything else],
}
```

**Landlock ABI versions:**
| ABI | Kernel | Features |
|-----|--------|----------|
| 1 | 5.13 | Basic filesystem |
| 2 | 5.19 | Truncate control |
| 3 | 6.2 | File permissions |
| 4 | 6.7 | Network TCP control |

**Security properties:**
- Enforced at kernel level (bypass-resistant)
- Works even if mount namespace bypassed
- Cannot be disabled after application

### Layer 6: Seccomp BPF

Syscall filtering with immediate termination on violation.

**Filter approach:** Whitelist (allow known-safe syscalls, kill on others)

**Blocked syscall categories:**
| Category | Syscalls | Reason |
|----------|----------|--------|
| Namespaces | `clone(CLONE_NEW*)`, `unshare`, `setns` | Prevent new namespaces |
| Mounting | `mount`, `umount`, `pivot_root` | Prevent FS manipulation |
| Debugging | `ptrace`, `process_vm_*` | Prevent process injection |
| Kernel | `reboot`, `kexec_load`, `init_module` | Prevent system damage |
| Privilege | `setuid`, `setgid`, `setgroups` | Prevent escalation |
| Keyring | `keyctl` | Not namespaced |
| eBPF | `bpf` | Kernel attack surface |

**Argument filtering:**
| Syscall | Blocked Arguments | Reason |
|---------|-------------------|--------|
| `clone` | `CLONE_NEWUSER`, `CLONE_NEWNET`, etc. | Block namespace creation |
| `socket` | `AF_NETLINK`, `SOCK_RAW` | Block kernel interfaces |
| `ioctl` | `TIOCSTI`, `TIOCSETD`, `TIOCLINUX` | Block terminal injection |

**Violation behavior:** `SECCOMP_RET_KILL_PROCESS` (SIGSYS, signal 31)

### Layer 7: Resource Limits

Prevent denial-of-service attacks.

| Resource | Limit | Purpose |
|----------|-------|---------|
| `RLIMIT_AS` | 256 MB | Memory limit |
| `RLIMIT_NPROC` | 64 | Fork bomb prevention |
| `RLIMIT_NOFILE` | 256 | File descriptor limit |
| `RLIMIT_FSIZE` | 10 MB | Output file size |
| Timeout | 30s | CPU time limit |

---

## Syscall Policy

### Allowed Syscalls (~100)

```
Basic I/O:     read, write, close, lseek, pread64, pwrite64
File ops:      openat, stat, fstat, access, readlink
Memory:        mmap, mprotect, munmap, brk, mremap
Process:       fork, vfork, execve, exit, exit_group, wait4
Signals:       rt_sigaction, rt_sigprocmask, rt_sigreturn
Time:          clock_gettime, nanosleep, gettimeofday
Sockets:       socket*, connect, bind, listen, accept, send*, recv*
Events:        epoll_*, poll, select
```

### Blocked Syscalls (examples)

```
Dangerous:     ptrace, mount, reboot, kexec_load, init_module
Namespaces:    clone3, unshare, setns (blocked or filtered)
Privilege:     setuid, setgid, setresuid, setresgid
Kernel:        bpf, perf_event_open, keyctl
Fileless:      memfd_create, execveat (together enable fileless exec)
```

### Special Handling

| Syscall | Handling |
|---------|----------|
| `clone` | Allowed, but `CLONE_NEW*` flags blocked |
| `clone3` | Returns `ENOSYS` (glibc falls back to `clone`) |
| `socket` | Allowed, but `AF_NETLINK` and `SOCK_RAW` blocked |
| `ioctl` | Allowed, but `TIOCSTI`, `TIOCSETD`, `TIOCLINUX` blocked |

---

## Threat Model

### In Scope (Protected Against)

| Threat | Mitigation |
|--------|------------|
| **Arbitrary code execution** | Sandboxed environment |
| **Filesystem escape** | Namespaces + Landlock + pivot_root |
| **Network access** | Network namespace (empty) |
| **Process injection** | PID namespace + ptrace blocked |
| **Privilege escalation** | User namespace + seccomp |
| **Resource exhaustion** | rlimits + timeouts |
| **Fork bombs** | RLIMIT_NPROC |
| **Terminal injection** | TIOCSTI/TIOCLINUX blocked |
| **Fileless malware** | memfd_create + execveat blocked |

### Out of Scope

| Threat | Reason |
|--------|--------|
| **Kernel exploits** | Requires kernel hardening (grsecurity, etc.) |
| **Side-channel attacks** | Spectre/Meltdown require CPU mitigations |
| **Container breakout via 0-day** | Defense in depth limits impact |
| **Covert channels** | Timing-based data exfiltration possible |

### CVE Protection

evalbox's seccomp policy blocks attack vectors for many kernel CVEs:

| CVE | Attack Vector | Blocked By |
|-----|---------------|------------|
| CVE-2024-1086 | AF_NETLINK + nf_tables | Socket filtering |
| CVE-2022-0185 | fsconfig + user namespace | CLONE_NEWUSER blocked |
| CVE-2022-0492 | cgroups + user namespace | CLONE_NEWUSER blocked |
| CVE-2017-5226 | TIOCSTI terminal injection | ioctl filtering |
| CVE-2019-13272 | ptrace PTRACE_TRACEME | ptrace blocked |
| CVE-2021-3490 | eBPF verifier bypass | bpf blocked |

---

## Filesystem Access

### Default Mounts

| Path | Access | Source | Purpose |
|------|--------|--------|---------|
| `/work` | Read-Write | Workspace | User files |
| `/tmp` | Read-Write | tmpfs | Temporary files |
| `/usr` | Read-Only | Host | Binaries, libraries |
| `/lib` | Read-Only | Host | Shared libraries |
| `/lib64` | Read-Only | Host | 64-bit libraries |
| `/etc` | Read-Only | Generated | Minimal config |
| `/dev` | Read-Only | Generated | null, zero, urandom |

### Not Mounted (Blocked)

| Path | Contains | Risk if Accessible |
|------|----------|-------------------|
| `/home` | User data | Data theft |
| `/root` | Root home | Credential theft |
| `/proc` | Process info | Info leak, escape vectors |
| `/sys` | Kernel interfaces | Kernel manipulation |
| `/var` | System state | Log manipulation |
| `/run` | Runtime data | Socket access |

---

## Verification

### Security Tests

Run the security test suite to verify isolation:

```bash
# Run all security tests
cargo test -p evalbox-sandbox --test security_tests -- --ignored

# Run specific category
cargo test -p evalbox-sandbox --test security_tests seccomp -- --ignored
cargo test -p evalbox-sandbox --test security_tests filesystem -- --ignored
cargo test -p evalbox-sandbox --test security_tests network -- --ignored
cargo test -p evalbox-sandbox --test security_tests cve -- --ignored
```

### Test Coverage

| Category | Tests | Coverage |
|----------|-------|----------|
| Seccomp | 9 | ptrace, mount, reboot, clone, socket, keyctl, bpf |
| Filesystem | 8 | /etc/shadow, /root, path traversal, symlinks |
| Network | 5 | External, localhost, loopback, DNS |
| Resources | 7 | Timeout, memory, PIDs, output limit |
| CVE | 10 | Real-world exploits blocked |

### Manual Verification

```bash
# Try to read /etc/shadow (should fail)
evalbox shell "cat /etc/shadow"

# Try to access network (should fail)
evalbox shell "curl https://example.com"

# Try ptrace (should be killed with SIGSYS)
evalbox shell "strace ls"
```

---

## Production Requirements

To deploy evalbox securely, ensure your system meets these requirements:

| Requirement | How to Verify |
|-------------|---------------|
| Kernel 5.13+ with Landlock | `cat /sys/kernel/security/lsm` should include `landlock` |
| User namespaces enabled | `cat /proc/sys/kernel/unprivileged_userns_clone` should be `1` |
| Seccomp enabled | `grep SECCOMP /boot/config-$(uname -r)` |
| Unprivileged BPF disabled | `sysctl kernel.unprivileged_bpf_disabled=1` (recommended) |

Run `evalbox check` to verify all requirements automatically.

---

## References

- [Architecture Overview](ARCHITECTURE.md)
- [Linux Namespaces](https://man7.org/linux/man-pages/man7/namespaces.7.html)
- [Landlock Documentation](https://docs.kernel.org/userspace-api/landlock.html)
- [Seccomp BPF](https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html)
