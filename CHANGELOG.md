# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

- **Security isolation** (7 layers of defense)
  - User namespaces (unprivileged containers)
  - PID namespace (process isolation)
  - Network namespace (network isolation)
  - Mount namespace + pivot_root (filesystem isolation)
  - Landlock LSM (kernel-enforced filesystem rules)
  - Seccomp BPF (syscall whitelist with ~100 allowed syscalls)
  - Resource limits (memory, PIDs, file descriptors, timeout)

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
