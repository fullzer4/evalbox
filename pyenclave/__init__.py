"""pyenclave: Run untrusted Python code safely with native Linux isolation.

This package provides a secure sandbox for executing untrusted Python code using
Linux namespaces, seccomp-BPF, Landlock LSM, and resource limits.

Example:
    >>> from pyenclave import run_python
    >>> result = run_python(code="print('Hello from sandbox!')")
    >>> print(result.stdout.decode())
    Hello from sandbox!

Main Components:
    - run_python: Execute Python code in isolated sandbox
    - probe: Check system security capabilities
    - ExecutionResult: Result dataclass with execution details
"""

from .api import list_interpreters, probe, run_python
from .exceptions import (
    ConfigurationError,
    ExecutionError,
    IsolationError,
    MountError,
    PolicyError,
    PreflightError,
    PyenclaveError,
    ResourceLimitError,
    SecurityError,
    TimeoutError,
    UnsupportedPlatformError,
)
from .result import ExecutionResult

__version__ = "0.1.0"

__all__ = [
    "run_python",
    "list_interpreters",
    "probe",
    "ExecutionResult",
    "PyenclaveError",
    "SecurityError",
    "IsolationError",
    "ExecutionError",
    "ConfigurationError",
    "UnsupportedPlatformError",
    "PreflightError",
    "PolicyError",
    "MountError",
    "TimeoutError",
    "ResourceLimitError",
]

