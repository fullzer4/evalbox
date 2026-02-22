# evalbox Security Model

## Defense in Depth

evalbox uses **independent isolation mechanisms**. Each provides protection even if another is bypassed.

```
┌─────────────────────────────────────────────────────────────┐
│           │      Landlock v5          │  Filesystem, Network│
│           │                           │  Signal, IPC        │
├───────────┼───────────────────────────┼─────────────────────┤
│           │      Seccomp BPF          │  Syscalls            │
├───────────┼───────────────────────────┼─────────────────────┤
│           │      rlimits              │  Resources           │
├───────────┼───────────────────────────┼─────────────────────┤
│           │   Privilege Hardening     │  NO_NEW_PRIVS,       │
│           │                           │  securebits, caps    │
└───────────┴───────────────────────────┴─────────────────────┘
```

---

## Isolation Mechanisms

### Landlock v5

Kernel-enforced access control (requires Linux 6.12+, Landlock ABI 5).

No namespaces or `pivot_root` needed — Landlock operates on real filesystem paths.

**Filesystem rules:**
```
read-only:   /usr, /lib, /lib64, /bin, /etc, /proc, /nix/store*
read-write:  workspace/work, workspace/tmp, workspace/home
write:       /dev (for /dev/null, /dev/zero, /dev/urandom)
no access:   everything else
```

**Network control (ABI 4+):**
- Blocks `LANDLOCK_ACCESS_NET_BIND_TCP`
- Blocks `LANDLOCK_ACCESS_NET_CONNECT_TCP`
- Optional: enable with `.network(true)`

**Signal isolation (ABI 5):**
- `LANDLOCK_SCOPE_SIGNAL` — blocks signals to processes outside the sandbox

**IPC isolation (ABI 5):**
- `LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET` — blocks connections to abstract unix sockets outside the sandbox

**Landlock ABI versions:**
| ABI | Kernel | Features |
|-----|--------|----------|
| 1 | 5.13 | Basic filesystem |
| 2 | 5.19 | Truncate control |
| 3 | 6.2 | File permissions |
| 4 | 6.7 | Network TCP control |
| 5 | 6.12 | Signal + abstract unix socket scoping |

**Security properties:**
- Enforced at kernel level (bypass-resistant)
- Cannot be disabled after application
- Works unprivileged with `NO_NEW_PRIVS`

### Seccomp BPF

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
| Fileless | `memfd_create`, `execveat` | Bypass Landlock |

**Argument filtering:**
| Syscall | Blocked Arguments | Reason |
|---------|-------------------|--------|
| `clone` | `CLONE_NEWUSER`, `CLONE_NEWNET`, `CLONE_NEWNS`, `CLONE_NEWPID`, `CLONE_NEWIPC`, `CLONE_NEWUTS`, `CLONE_NEWCGROUP` | Block namespace creation |
| `clone3` | Entirely blocked (returns `ENOSYS`) | Cannot inspect flags in userspace struct |
| `socket` | `AF_NETLINK`, `SOCK_RAW` | Block kernel interfaces |
| `ioctl` | `TIOCSTI`, `TIOCSETD`, `TIOCLINUX` | Block terminal injection |

**Violation behavior:** `SECCOMP_RET_KILL_PROCESS` (SIGSYS, signal 31)

### Resource Limits

Prevent denial-of-service attacks via kernel-enforced rlimits.

| Resource | Limit | Purpose |
|----------|-------|---------|
| `RLIMIT_DATA` | 256 MiB | Memory usage |
| `RLIMIT_CPU` | timeout * 2 + 60s | CPU time limit |
| `RLIMIT_FSIZE` | 16 MiB | Output file size |
| `RLIMIT_NOFILE` | 256 | File descriptor limit |
| `RLIMIT_NPROC` | 64 | Fork bomb prevention |
| `RLIMIT_CORE` | 0 | Core dumps disabled |
| `RLIMIT_STACK` | 8 MiB | Stack size |

Note: `RLIMIT_AS` (virtual address space) is intentionally not set. Modern runtimes like Go, Java, and V8 pre-allocate large virtual ranges but only commit small portions.

### Privilege Hardening

Permanent privilege reduction applied before seccomp:

| Mechanism | Effect |
|-----------|--------|
| `PR_SET_NO_NEW_PRIVS` | Cannot gain privileges via exec (setuid, file caps) |
| `SECBIT_NOROOT` (locked) | Root has no special privilege |
| `SECBIT_NO_SETUID_FIXUP` (locked) | Capabilities not adjusted on UID change |
| `SECBIT_KEEP_CAPS` (locked) | Cannot keep caps through exec |
| `SECBIT_NO_CAP_AMBIENT_RAISE` (locked) | Cannot set ambient capabilities |
| Drop all 64 capabilities | No capability-based operations possible |

---

## Syscall Policy

### Allowed Syscalls (~100)

```
Basic I/O:     read, write, close, lseek, pread64, pwrite64
File ops:      openat, stat, fstat, access, readlink
Memory:        mmap, mprotect, munmap, brk, mremap
Process:       fork, vfork, execve, exit, exit_group, wait4
Signals:       rt_sigaction, rt_sigprocmask, rt_sigreturn, kill, tgkill
Time:          clock_gettime, nanosleep, gettimeofday
Sockets:       socket*, connect, bind, listen, accept, send*, recv*
Events:        epoll_*, poll, select
```

Note: `kill` and `tgkill` are allowed because Landlock ABI 5 provides signal scoping — signals can only reach processes within the sandbox.

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
| **Filesystem escape** | Landlock v5 path rules |
| **Network access** | Landlock network control (ABI 4+) + seccomp socket filtering |
| **Process injection** | ptrace blocked by seccomp |
| **Privilege escalation** | NO_NEW_PRIVS + seccomp + capability drop |
| **Resource exhaustion** | rlimits + timeouts |
| **Fork bombs** | RLIMIT_NPROC |
| **Terminal injection** | TIOCSTI/TIOCLINUX blocked by seccomp |
| **Fileless malware** | memfd_create + execveat blocked by seccomp |
| **Cross-sandbox signals** | Landlock signal scoping (ABI 5) |
| **Abstract unix socket abuse** | Landlock IPC scoping (ABI 5) |

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

### Accessible Paths (via Landlock)

| Path | Access | Purpose |
|------|--------|---------|
| `workspace/work` | Read-Write | User files |
| `workspace/tmp` | Read-Write | Temporary files |
| `workspace/home` | Read-Write | Home directory |
| `/usr` | Read-Only + Execute | Binaries, libraries |
| `/lib` | Read-Only + Execute | Shared libraries |
| `/lib64` | Read-Only + Execute | 64-bit libraries |
| `/bin` | Read-Only + Execute | Binaries |
| `/etc` | Read-Only | System config |
| `/proc` | Read-Only | Process info (no execute) |
| `/dev` | Read + Write | null, zero, urandom |
| `/nix/store` | Read-Only + Execute | NixOS paths (if present) |

### Not Accessible

| Path | Contains | Risk if Accessible |
|------|----------|-------------------|
| `/home` (host) | User data | Data theft |
| `/root` | Root home | Credential theft |
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

Or via Nix:

```bash
nix run .#test-all
```

### Test Coverage

| Category | Tests | Coverage |
|----------|-------|----------|
| Seccomp | 9 | ptrace, mount, reboot, clone, socket, keyctl, bpf |
| Filesystem | 8 | /etc/shadow, /root, path traversal, symlinks |
| Network | 5 | External, localhost, loopback, DNS |
| Resources | 7 | Timeout, memory, PIDs, output limit |
| CVE | 10 | Real-world exploits blocked |

---

## Production Requirements

| Requirement | How to Verify |
|-------------|---------------|
| Kernel 6.12+ | `uname -r` |
| Landlock ABI 5 | `cat /sys/kernel/security/lsm` should include `landlock` |
| Seccomp enabled | `grep SECCOMP /boot/config-$(uname -r)` |
| Unprivileged BPF disabled | `sysctl kernel.unprivileged_bpf_disabled=1` (recommended) |

Run `evalbox check` to verify all requirements automatically.

---

## References

- [Architecture](ARCHITECTURE.md)
- [Security Policy](../SECURITY.md)
- [Landlock Documentation](https://docs.kernel.org/userspace-api/landlock.html)
- [Seccomp BPF](https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html)
