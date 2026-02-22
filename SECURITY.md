# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a Vulnerability

If you discover a security vulnerability in evalbox, **please do not open a public issue.**

Instead, report it privately via [GitHub Security Advisories](https://github.com/fullzer4/evalbox/security/advisories/new).

Include:
- Description of the vulnerability
- Steps to reproduce
- Which isolation mechanism is affected (Landlock, seccomp, rlimits, privilege hardening)
- Impact assessment (sandbox escape, info leak, DoS, etc.)

You should receive a response within **72 hours**. Critical sandbox escape vulnerabilities are treated as highest priority.

## Scope

evalbox provides isolation via Landlock v5, seccomp-BPF, rlimits, and privilege hardening. The following are in scope for security reports:

- Sandbox escape (code executing outside isolation)
- Filesystem access beyond Landlock-allowed paths
- Network access when disabled
- Privilege escalation from sandbox
- Seccomp filter bypass
- Landlock rule bypass
- Resource limit bypass (memory, PIDs, file descriptors)

See [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md) for the full threat model and isolation architecture.

## Out of Scope

- Kernel 0-day exploits (requires kernel hardening)
- CPU side-channel attacks (Spectre/Meltdown)
- Denial of service against the host kernel
- Issues requiring non-default kernel configurations
