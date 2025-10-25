# pyenclave

Hermetic, multi-version Python runner for untrusted code on Linux — using namespaces, seccomp-BPF, Landlock and rlimits. Built as a single Python package (PyO3).

> **Status**: skeleton

## Highlights
- Linux-only; no external daemon/containers.
- Multi-Python (3.8+), BYO venv/conda (RO).
- No network by default, minimal syscalls, FS allowlist.
- Stateless by default; opt-in state via RW mounts.

See `docs/` (a criar) e comentários *TODO* nos arquivos para implementar cada etapa.
