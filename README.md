# pyenclave

**Run untrusted Python code safely with native Linux isolation. No containers needed.**

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Linux](https://img.shields.io/badge/platform-linux-green.svg)](https://www.kernel.org/)

`pyenclave` is a hermetic Python sandbox that executes untrusted code using native Linux security features: **user namespaces**, **seccomp-BPF**, **Landlock LSM**, and **resource limits**. Built as a single Python package with a Rust core (PyO3).

> **Status**: Alpha - Core functionality implemented, production-ready features in progress

## ✨ Features

- 🔒 **Multi-layer isolation**: User namespaces + seccomp + Landlock + rlimits
- 🐍 **Multi-Python support**: Python 3.8+ with BYO venv/conda (read-only)
- 🚫 **Network isolation**: No network access by default
- 📁 **Filesystem control**: Minimal syscalls, explicit allowlist
- ⚡ **Stateless by default**: Ephemeral execution with opt-in persistence
- 🏗️ **No external dependencies**: Pure Linux, no Docker/containers
- 🦀 **High performance**: Rust core with Python API

## 🚀 Quick Start

### Installation

```bash
# From PyPI (when published)
pip install pyenclave

# From source
git clone https://github.com/fullzer4/pyenclave
cd pyenclave
pip install -e .
```

### Basic Usage

```python
from pyenclave import run_python

# Execute untrusted code
result = run_python(code="print('Hello from sandbox!')")
print(result.stdout.decode())  # Hello from sandbox!
print(result.exit_code)         # 0

# With resource limits
result = run_python(
    code="import time; time.sleep(10)",
    time_limit_s=2,
    memory_limit_mb=128
)

# With filesystem access
result = run_python(
    script="/path/to/script.py",
    mounts={"ro": [["/data", "/data"]]},
    network=False
)
```

## 📋 Requirements

- **OS**: Linux kernel 5.10+ (6.1+ recommended for full Landlock support)
- **Python**: 3.8 or higher
- **Architecture**: x86_64, aarch64

Check system compatibility:
```bash
pyenclave probe
```

## 🤝 Contributing

Contributions welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

Areas of interest:
- Additional seccomp profiles
- Support for more architectures
- Performance optimizations
- Documentation improvements

---

**⚠️ Security Notice**: While `pyenclave` provides strong isolation, no sandbox is 100% secure. Always run with defense in depth and monitor for kernel vulnerabilities. See [SECURITY.md](SECURITY.md) for details.
