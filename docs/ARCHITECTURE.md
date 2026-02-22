# evalbox Architecture

## Overview

evalbox is a secure sandbox for executing untrusted code on Linux. It provides millisecond-startup isolation using Landlock LSM v5, seccomp-BPF, and rlimits — no namespaces, no containers, no root.

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
│  │   • Landlock v5 (filesystem, network, signal, IPC)       │   │
│  │   • Seccomp-BPF (syscall whitelist)                      │   │
│  │   • rlimits (memory, CPU, PIDs, fds)                     │   │
│  │   • Privilege hardening (securebits, capability drop)    │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                      evalbox-sys                                 │
│   Raw Linux syscalls: seccomp, landlock, seccomp_notify          │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                       Linux Kernel                               │
│           seccomp-bpf │ landlock │ rlimits                       │
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
│       │   ├── lockdown.rs  # Landlock v5 + securebits + cap drop
│       │   └── rlimits.rs   # Resource limits
│       ├── notify/          # Seccomp user notify (optional)
│       ├── validate.rs      # Input validation
│       └── resolve.rs       # Binary resolution
│
└── evalbox-sys/             # Low-level syscalls
    └── src/
        ├── seccomp.rs       # BPF filter generation
        ├── seccomp_notify.rs # Seccomp user notify support
        ├── landlock.rs      # Landlock ruleset API
        └── check.rs         # System capability detection
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
│     • Create writable directories: /work, /tmp, /home           │
│     • Write user files to /work                                  │
│     • Create pipes (stdin, stdout, stderr) + eventfd sync       │
└──────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌──────────────────────────────────────────────────────────────────┐
│  3. FORK                                                         │
│     fork() — plain fork, no CLONE_NEW* flags                    │
│                                                                  │
│     Parent                          Child                        │
│       │                               │                          │
│       ├─ Open pidfd                   ├─ Close parent pipe ends  │
│       ├─ Wait for child ready         ├─ Setup stdio (dup2)     │
│       ├─ Signal to proceed            ├─ chdir(workspace/work)  │
│       ▼                               ├─ Apply lockdown (step 4)│
│                                       ▼                          │
└──────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌──────────────────────────────────────────────────────────────────┐
│  4. CHILD LOCKDOWN (irreversible)                                │
│                                                                  │
│     ┌─────────────────────────────────────────────────────────┐ │
│     │  a) NO_NEW_PRIVS                                        │ │
│     │     prctl(PR_SET_NO_NEW_PRIVS) — required before        │ │
│     │     Landlock and seccomp                                │ │
│     └─────────────────────────────────────────────────────────┘ │
│     ┌─────────────────────────────────────────────────────────┐ │
│     │  b) Landlock v5                                         │ │
│     │     • Filesystem: read-only /usr, /lib, /etc, /bin      │ │
│     │       read-write workspace/work, /tmp, /home            │ │
│     │     • Network: block TCP bind + connect (ABI 4+)        │ │
│     │     • Signals: block cross-sandbox signals (ABI 5)      │ │
│     │     • IPC: block abstract unix sockets (ABI 5)          │ │
│     └─────────────────────────────────────────────────────────┘ │
│     ┌─────────────────────────────────────────────────────────┐ │
│     │  c) Resource limits (rlimits)                           │ │
│     │     • RLIMIT_DATA: 256 MiB memory                       │ │
│     │     • RLIMIT_CPU: timeout * 2 + 60s                     │ │
│     │     • RLIMIT_NPROC: 64 processes                        │ │
│     │     • RLIMIT_NOFILE: 256 file descriptors               │ │
│     │     • RLIMIT_FSIZE: 16 MiB output                       │ │
│     │     • RLIMIT_CORE: 0 (disabled)                         │ │
│     │     • RLIMIT_STACK: 8 MiB                               │ │
│     └─────────────────────────────────────────────────────────┘ │
│     ┌─────────────────────────────────────────────────────────┐ │
│     │  d) Securebits + capability drop                        │ │
│     │     • Lock NOROOT, NO_SETUID_FIXUP, KEEP_CAPS,          │ │
│     │       NO_CAP_AMBIENT_RAISE                              │ │
│     │     • Drop all 64 capabilities                          │ │
│     └─────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌──────────────────────────────────────────────────────────────────┐
│  5. SECCOMP FILTERS                                              │
│     • [Optional] Install notify filter for FS syscall            │
│       interception, send listener fd to parent via SCM_RIGHTS   │
│     • Install kill filter — whitelist of ~100 safe syscalls     │
│     • Argument filtering: clone flags, socket domains, ioctls   │
│     • Violation = SECCOMP_RET_KILL_PROCESS (SIGSYS)             │
└──────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌──────────────────────────────────────────────────────────────────┐
│  6. SIGNAL PARENT + WAIT + EXEC                                  │
│     • Signal parent readiness (eventfd)                          │
│     • Wait for parent go-ahead (eventfd)                        │
│     • close_range(3, MAX, 0) — close all fds except 0,1,2      │
│     • execve(binary, args, env)                                  │
│                                                                  │
│     All isolation is now permanent and cannot be undone.         │
└──────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌──────────────────────────────────────────────────────────────────┐
│  7. PARENT MONITORS                                              │
│     • Poll pidfd for process exit                               │
│     • Read stdout/stderr via pipes                              │
│     • Enforce timeout (kill if exceeded)                        │
│     • Track output size (kill if exceeded)                      │
└──────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌──────────────────────────────────────────────────────────────────┐
│  8. CLEANUP                                                      │
│     • Collect exit status                                        │
│     • Remove workspace tempdir                                   │
│     • Return Output { stdout, stderr, exit_code, signal }       │
└──────────────────────────────────────────────────────────────────┘
```

---

## Security Architecture

evalbox implements **defense in depth** with independent isolation mechanisms:

```
┌─────────────────────────────────────────────────────────────┐
│                   UNTRUSTED CODE                             │
└─────────────────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────┐
│  Landlock v5                                                 │
│  • Filesystem: read-only system paths, read-write workspace │
│  • Network: block TCP bind + connect (ABI 4+)               │
│  • Signals: block cross-sandbox signals (ABI 5)             │
│  • IPC: block abstract unix sockets (ABI 5)                 │
└─────────────────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────┐
│  Seccomp BPF                                                 │
│  • ~100 allowed syscalls (whitelist)                        │
│  • Blocks ptrace, mount, clone(NEWUSER), AF_NETLINK         │
│  • SIGSYS on violation (immediate termination)              │
└─────────────────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────┐
│  Resource Limits                                             │
│  • Memory, CPU, processes, file descriptors                 │
│  • Prevents DoS attacks                                      │
└─────────────────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────┐
│  Privilege Hardening                                         │
│  • NO_NEW_PRIVS — cannot gain privileges via exec           │
│  • Securebits locked — cannot regain capabilities           │
│  • All 64 capabilities dropped                              │
└─────────────────────────────────────────────────────────────┘

For detailed security policy and threat model, see SECURITY_MODEL.md
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

For the complete syscall policy, see [SECURITY_MODEL.md](SECURITY_MODEL.md#syscall-policy).

---

## Workspace Structure

```
/tmp/evalbox-XXXXX/           Workspace root (tmpdir)
├── work/                     User workspace (read-write via Landlock)
│   ├── script.py             User files
│   └── data.json
├── tmp/                      Temporary files (read-write via Landlock)
└── home/                     Home directory (read-write via Landlock)
```

The workspace is a plain tempdir. No `pivot_root`, no bind mounts, no special rootfs. Landlock rules control which real filesystem paths are accessible.

---

## Design Principles

### 1. Simple as eval()
```rust
// One function call to run code safely
let output = python::run("print('hello')").exec()?;
```

### 2. Defense in Depth
Each isolation mechanism works independently. Landlock controls filesystem and network access, seccomp blocks dangerous syscalls, rlimits prevent resource exhaustion. See [SECURITY_MODEL.md](SECURITY_MODEL.md#defense-in-depth).

### 3. Unprivileged
- No root required
- No daemon/service
- No namespaces needed — Landlock + seccomp work unprivileged with `NO_NEW_PRIVS`

### 4. Minimal Attack Surface
- Small syscall whitelist (~100 syscalls)
- Landlock restricts filesystem to minimal paths
- All capabilities dropped

### 5. Fast
- ~5ms sandbox creation
- No VM boot, no container image pull
- Plain `fork()` + lockdown

### 6. Embeddable
- Library, not a service
- No external dependencies
- Works in existing applications

---

## System Requirements

| Requirement | Minimum |
|-------------|---------|
| Linux Kernel | 6.12 |
| Landlock | ABI 5 |
| Seccomp | Required |

Check compatibility:
```bash
evalbox check
```

---

## References

- [Security Model](SECURITY_MODEL.md) - Detailed security model and threat analysis
- [Roadmap](ROADMAP.md) - Planned features
- [Landlock LSM](https://docs.kernel.org/userspace-api/landlock.html)
- [Seccomp BPF](https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html)
