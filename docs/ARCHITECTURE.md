# evalbox Architecture

## Overview

evalbox is a secure sandbox for executing untrusted code on Linux. It provides millisecond-startup isolation using Linux namespaces, Landlock LSM, and seccomp-BPF.

```
┌─────────────────────────────────────────────────────────────────┐
│                        User Application                          │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                    evalbox (Public API)                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐  │
│  │   Python    │  │    Shell    │  │      Plan Builder       │  │
│  │   Runtime   │  │   Runtime   │  │   (low-level control)   │  │
│  └─────────────┘  └─────────────┘  └─────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                    evalbox-sandbox                               │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                      Executor                             │   │
│  │   • Event loop (mio + epoll)                             │   │
│  │   • Concurrent sandbox management                        │   │
│  │   • Output streaming                                      │   │
│  └──────────────────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                     Isolation                             │   │
│  │   • Namespaces (user, pid, net, mount, uts, ipc)         │   │
│  │   • pivot_root + minimal rootfs                          │   │
│  │   • Landlock filesystem rules                            │   │
│  │   • Seccomp syscall filter                               │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                      evalbox-sys                                 │
│   Raw Linux syscalls: clone3, pidfd, seccomp, landlock          │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                       Linux Kernel                               │
│   namespaces │ seccomp-bpf │ landlock │ cgroups │ rlimits       │
└─────────────────────────────────────────────────────────────────┘
```

---

## Crate Structure

```
evalbox/
├── evalbox/                 # Public API, language runtimes
│   └── src/
│       ├── lib.rs           # Re-exports
│       ├── python.rs        # Python runtime
│       └── shell.rs         # Shell runtime
│
├── evalbox-sandbox/         # Sandbox orchestration
│   └── src/
│       ├── executor.rs      # Event loop, concurrent execution
│       ├── plan.rs          # Execution plan builder
│       ├── workspace.rs     # Temporary filesystem setup
│       ├── monitor.rs       # Process monitoring, output capture
│       ├── isolation/       # Isolation mechanisms
│       │   ├── namespace.rs # User/PID/Net namespace setup
│       │   ├── rootfs.rs    # Mount namespace, pivot_root
│       │   └── lockdown.rs  # Landlock + seccomp application
│       ├── validate.rs      # Input validation
│       └── sysinfo.rs       # System detection (Nix, paths)
│
└── evalbox-sys/             # Low-level syscalls
    └── src/
        ├── seccomp.rs       # BPF filter generation
        ├── landlock.rs      # Landlock ruleset API
        └── check.rs         # Capability detection
```

---

## Executor

The Executor manages concurrent sandbox execution using a single-threaded event loop.

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Executor                              │
│  ┌────────────────────────────────────────────────────────┐ │
│  │                    mio Poll                             │ │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐              │ │
│  │  │  pidfd   │  │  stdout  │  │  stderr  │  ...         │ │
│  │  │ sandbox1 │  │ sandbox1 │  │ sandbox1 │              │ │
│  │  └──────────┘  └──────────┘  └──────────┘              │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐ │
│  │               Active Sandboxes Map                      │ │
│  │   id:0 → { pidfd, workspace, pipes, state }            │ │
│  │   id:1 → { pidfd, workspace, pipes, state }            │ │
│  └────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

### Usage Patterns

```rust
// Pattern 1: Simple blocking execution
let output = Executor::run(plan)?;

// Pattern 2: Concurrent execution with event loop
let mut executor = Executor::new()?;
let id1 = executor.spawn(plan1)?;
let id2 = executor.spawn(plan2)?;

let mut events = Vec::new();
loop {
    executor.poll(&mut events, None)?;
    for event in events.drain(..) {
        match event {
            Event::Completed { id, output } => { /* handle */ }
            Event::Stdout { id, data } => { /* stream */ }
        }
    }
    if executor.active_count() == 0 { break; }
}
```

### Platform Behavior

| Platform | Process Monitoring | I/O Multiplexing |
|----------|-------------------|------------------|
| Linux    | pidfd + epoll     | mio (epoll)      |
| macOS    | vsock to VM       | mio (kqueue)     |

---

## Sandbox Lifecycle

```
┌──────────────────────────────────────────────────────────────────┐
│  1. PLAN CREATION                                                │
│     Plan::new(["python", "-c", code])                           │
│       .timeout(5s)                                               │
│       .memory_limit(256MB)                                       │
│       .file("script.py", code)                                  │
└──────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌──────────────────────────────────────────────────────────────────┐
│  2. WORKSPACE PREPARATION                                        │
│     • Create tempdir (/tmp/evalbox-XXXXX)                       │
│     • Setup directory structure (/work, /tmp, /etc)             │
│     • Write user files                                           │
│     • Create pipes (stdin, stdout, stderr)                      │
└──────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌──────────────────────────────────────────────────────────────────┐
│  3. CLONE WITH NAMESPACES                                        │
│     clone3(CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNET |        │
│            CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC)           │
│                                                                  │
│     Parent                          Child                        │
│       │                               │                          │
│       ├─ Write UID/GID maps           ├─ Wait for parent        │
│       ├─ Signal ready ────────────────►                          │
│       │                               ├─ Setup isolation        │
│       │                               │   (see step 4)          │
│       ▼                               ▼                          │
└──────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌──────────────────────────────────────────────────────────────────┐
│  4. CHILD ISOLATION SETUP                                        │
│                                                                  │
│     ┌─────────────────────────────────────────────────────────┐ │
│     │  a) Mount namespace                                      │ │
│     │     • Bind mount /usr, /lib, /lib64 (read-only)         │ │
│     │     • Bind mount workspace to /work                      │ │
│     │     • Mount minimal /dev (null, zero, urandom)          │ │
│     │     • pivot_root to new root                            │ │
│     │     • Unmount old root                                   │ │
│     └─────────────────────────────────────────────────────────┘ │
│     ┌─────────────────────────────────────────────────────────┐ │
│     │  b) Landlock (kernel 5.13+)                              │ │
│     │     • Create ruleset with FS restrictions               │ │
│     │     • Allow read-only: /usr, /lib, /bin, /etc           │ │
│     │     • Allow read-write: /work, /tmp                     │ │
│     │     • Enforce ruleset                                    │ │
│     │     (See SECURITY.md for details)                       │ │
│     └─────────────────────────────────────────────────────────┘ │
│     ┌─────────────────────────────────────────────────────────┐ │
│     │  c) Seccomp BPF                                          │ │
│     │     • Load syscall whitelist filter                     │ │
│     │     • Block dangerous syscalls (ptrace, mount, etc.)    │ │
│     │     • Filter clone() flags, socket() domains            │ │
│     │     • Filter dangerous ioctls (TIOCSTI, etc.)           │ │
│     │     (See SECURITY.md for full policy)                   │ │
│     └─────────────────────────────────────────────────────────┘ │
│     ┌─────────────────────────────────────────────────────────┐ │
│     │  d) Resource limits (rlimits)                           │ │
│     │     • RLIMIT_AS: Memory limit                           │ │
│     │     • RLIMIT_NPROC: Process limit                       │ │
│     │     • RLIMIT_NOFILE: File descriptor limit              │ │
│     │     • RLIMIT_FSIZE: Output file size limit              │ │
│     └─────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌──────────────────────────────────────────────────────────────────┐
│  5. EXECVE TARGET PROGRAM                                        │
│     execve("/usr/bin/python", ["python", "-c", code], env)      │
│                                                                  │
│     • All isolation is now permanent                            │
│     • Seccomp filter cannot be removed                          │
│     • Landlock rules cannot be relaxed                          │
└──────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌──────────────────────────────────────────────────────────────────┐
│  6. PARENT MONITORS                                              │
│     • Poll pidfd for process exit                               │
│     • Read stdout/stderr via pipes                              │
│     • Enforce timeout (kill if exceeded)                        │
│     • Track output size (truncate if exceeded)                  │
└──────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌──────────────────────────────────────────────────────────────────┐
│  7. CLEANUP                                                      │
│     • Collect exit status                                        │
│     • Remove workspace tempdir                                   │
│     • Return Output { stdout, stderr, exit_code, signal }       │
└──────────────────────────────────────────────────────────────────┘
```

---

## Security Architecture

evalbox implements **defense in depth** with 7 independent isolation layers:

```
┌─────────────────────────────────────────────────────────────┐
│                   UNTRUSTED CODE                             │
└─────────────────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────┐
│  Layer 1: User Namespace                                     │
│  • UID 0 inside = real user outside                         │
│  • No capabilities in parent namespace                      │
└─────────────────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────┐
│  Layer 2: PID Namespace                                      │
│  • Isolated process tree (PID 1 inside)                     │
│  • Cannot see/signal host processes                         │
└─────────────────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────┐
│  Layer 3: Network Namespace                                  │
│  • Empty by default (no interfaces)                         │
│  • Cannot access host network                               │
└─────────────────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────┐
│  Layer 4: Mount Namespace + pivot_root                       │
│  • Minimal rootfs (no /proc, /sys, /home)                   │
│  • Host filesystem completely unmounted                     │
└─────────────────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────┐
│  Layer 5: Landlock LSM                                       │
│  • Kernel-enforced filesystem rules                         │
│  • Read-only binaries, read-write workspace only            │
└─────────────────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────┐
│  Layer 6: Seccomp BPF                                        │
│  • ~100 allowed syscalls (whitelist)                        │
│  • Blocks ptrace, mount, clone(NEWUSER), AF_NETLINK         │
│  • SIGSYS on violation (immediate termination)              │
└─────────────────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────┐
│  Layer 7: Resource Limits                                    │
│  • Memory, CPU, processes, file descriptors                 │
│  • Prevents DoS attacks                                      │
└─────────────────────────────────────────────────────────────┘

For detailed security policy and threat model, see SECURITY.md
```

---

## Seccomp Filter Architecture

The seccomp BPF filter is generated at runtime with syscall-specific handling:

```
BPF Program Flow:
─────────────────

┌─────────────────────────────────────────────────────────────┐
│  Load architecture from seccomp_data                        │
│  if arch != x86_64 → KILL                                   │
└─────────────────────────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────────────────┐
│  Load syscall number                                         │
└─────────────────────────────────────────────────────────────┘
                    │
        ┌───────────┼───────────┬───────────┬───────────┐
        ▼           ▼           ▼           ▼           ▼
   ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐
   │ clone3  │ │  clone  │ │ socket  │ │  ioctl  │ │ other   │
   │ → ERRNO │ │ → check │ │ → check │ │ → check │ │ → check │
   │ (ENOSYS)│ │  flags  │ │ domain  │ │  cmd    │ │ whitelist│
   └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘
                    │           │           │           │
                    ▼           ▼           ▼           ▼
              ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐
              │CLONE_NEW│ │AF_NETLINK│ │TIOCSTI │ │in list? │
              │  flags? │ │SOCK_RAW?│ │TIOCSETD│ │         │
              └─────────┘ └─────────┘ └─────────┘ └─────────┘
                 │  │        │  │        │  │        │  │
              yes│  │no   yes│  │no   yes│  │no   yes│  │no
                 ▼  ▼        ▼  ▼        ▼  ▼        ▼  ▼
               KILL ALLOW  KILL ALLOW  KILL ALLOW ALLOW KILL
```

For the complete syscall policy, see [SECURITY.md](SECURITY.md#syscall-policy).

---

## Workspace Structure

```
/tmp/evalbox-XXXXX/           Workspace root (tmpdir)
├── root/                     New root filesystem
│   ├── work/                 User workspace (read-write)
│   │   ├── script.py         User files
│   │   └── data.json
│   ├── tmp/                  Temporary files (read-write)
│   ├── etc/                  Minimal config
│   │   ├── passwd            nobody user
│   │   ├── group             nogroup
│   │   ├── hosts             localhost
│   │   └── resolv.conf       DNS (if network enabled)
│   ├── dev/                  Minimal devices
│   │   ├── null
│   │   ├── zero
│   │   ├── urandom
│   │   └── fd → /proc/self/fd
│   ├── usr/ ──────────────── Bind mount (read-only)
│   ├── lib/ ──────────────── Bind mount (read-only)
│   ├── lib64/ ────────────── Bind mount (read-only)
│   └── bin/ ──────────────── Symlink to /usr/bin
│
├── stdin                     Input pipe
├── stdout                    Output pipe
└── stderr                    Error pipe
```

---

## Design Principles

### 1. Simple as eval()
```rust
// One function call to run code safely
let output = python::run("print('hello')", &config)?;
```

### 2. Defense in Depth
Every isolation mechanism works independently. A bypass of one layer doesn't compromise the sandbox. See [SECURITY.md](SECURITY.md#defense-in-depth).

### 3. Unprivileged
- No root required
- No daemon/service
- Uses user namespaces

### 4. Minimal Attack Surface
- Small syscall whitelist (~100 syscalls)
- Minimal filesystem
- No /proc, /sys by default

### 5. Fast
- ~5ms sandbox creation
- No VM boot
- No container image pull

### 6. Embeddable
- Library, not a service
- No external dependencies
- Works in existing applications

---

## System Requirements

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| Linux Kernel | 5.13 | 6.1+ |
| User Namespaces | Required | - |
| Landlock | Required (ABI 1) | ABI 4 |
| Seccomp | Required | - |

Check compatibility:
```bash
evalbox check
```

---

## References

- [SECURITY.md](SECURITY.md) - Detailed security model and threat analysis
- [ROADMAP.md](ROADMAP.md) - Planned features
- [Linux namespaces](https://man7.org/linux/man-pages/man7/namespaces.7.html)
- [Landlock LSM](https://docs.kernel.org/userspace-api/landlock.html)
- [Seccomp BPF](https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html)
