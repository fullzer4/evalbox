# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2026-02-22

### Changed

- **Architecture: remove namespace isolation, use Landlock v5 as primary**
  - Removed user, PID, network, mount, UTS, and IPC namespaces
  - Removed `pivot_root` and bind mount rootfs setup
  - Landlock v5 replaces namespaces for filesystem, network, signal, and IPC control
  - Plain `fork()` instead of `clone()` with `CLONE_NEW*` flags
  - Minimum kernel raised from 5.13 to 6.12 (Landlock ABI 5)

- **Resource limits moved to dedicated module** (`isolation/rlimits.rs`)
  - `RLIMIT_DATA` (256 MiB) instead of `RLIMIT_AS` (breaks Go/Java/V8 runtimes)
  - Added `RLIMIT_CPU`, `RLIMIT_CORE`, `RLIMIT_STACK`

- **Nix flake migrated to flake-parts + import-tree**
  - Auto-discovery of modules via `import-tree ./nix`
  - Removed manual `forAllSystems` boilerplate
  - Restricted to `x86_64-linux` (arm not yet supported)

### Added

- Seccomp user notify support (`SECCOMP_RET_USER_NOTIF`) for optional syscall interception
- `nix run .#test-all` to run the full security test suite
- `SECURITY.md` — GitHub standard vulnerability reporting policy
- `CONTRIBUTING.md` — development setup, testing guide
- Security hardening roadmap (UDP filtering, /proc restriction, optional PID namespace)

### Removed

- `crates/evalbox-sandbox/src/isolation/namespace.rs` — namespace setup
- `crates/evalbox-sandbox/src/isolation/rootfs.rs` — pivot_root + bind mounts
- `nix/lib.nix`, `nix/checks.nix`, `nix/tests/` — replaced by flake-parts modules

## [0.1.0] - 2025-02-17

### Added

- **Core sandbox execution**
  - `Executor::run(plan)` for blocking execution
  - `Plan` builder for configuring sandbox execution
  - Concurrent sandbox management via mio-based event loop

- **Language runtimes**
  - Python runtime with auto-detection
  - Go runtime with compilation caching
  - Shell runtime for script execution

- **Security isolation**
  - Landlock v5 (filesystem, network, signal, IPC access control)
  - Seccomp BPF (syscall whitelist with ~100 allowed syscalls)
  - Resource limits (memory, PIDs, file descriptors, timeout)
  - Privilege hardening (NO_NEW_PRIVS, securebits, capability drop)

- **Seccomp filtering**
  - Whitelist-based syscall filter
  - Argument filtering for `clone()`, `socket()`, `ioctl()`
  - Blocks dangerous syscalls: ptrace, mount, reboot, bpf, keyctl
  - Blocks dangerous ioctls: TIOCSTI, TIOCSETD, TIOCLINUX
  - Blocks dangerous sockets: AF_NETLINK, SOCK_RAW

- **Security test suite** (39 tests)
  - CVE-specific tests (CVE-2024-1086, CVE-2022-0185, CVE-2017-5226, etc.)
  - Seccomp validation tests
  - Filesystem isolation tests
  - Network isolation tests
  - Resource limit tests

- **Documentation**
  - Architecture documentation with diagrams
  - Security model documentation
  - Threat model and CVE protection list

- **CI/CD**
  - GitHub Actions workflow for CI
  - release-plz integration for automated releases
  - SemVer checking with cargo-semver-checks

### Security

- Blocks CVE-2024-1086 (nf_tables) via AF_NETLINK socket filtering
- Blocks CVE-2022-0185 (fsconfig) via CLONE_NEWUSER filtering
- Blocks CVE-2022-0492 (cgroups escape) via namespace creation blocking
- Blocks CVE-2017-5226 (TIOCSTI) via ioctl filtering
- Blocks fileless execution (memfd_create + execveat)
- Blocks user namespace creation inside sandbox
- Blocks ptrace-based attacks
