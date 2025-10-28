"""
Exceções específicas do pyenclave.
"""


class PyenclaveError(Exception):
    """Base exception for all pyenclave errors."""
    pass


class PreflightError(PyenclaveError):
    """Raised when preflight checks fail (probe)."""
    pass


class PolicyError(PyenclaveError):
    """Raised when security policy configuration is invalid."""
    pass


class MountError(PyenclaveError):
    """Raised when mount configuration is invalid."""
    pass


class TimeoutError(PyenclaveError):
    """Raised when execution exceeds time limit."""
    pass


class ResourceLimitError(PyenclaveError):
    """Raised when resource limits are exceeded."""
    pass


class SecurityError(PyenclaveError):
    """Raised when a security check fails."""
    pass


class IsolationError(PyenclaveError):
    """Raised when isolation setup fails (namespaces, seccomp, landlock)."""
    pass


class ExecutionError(PyenclaveError):
    """Raised when code execution fails."""
    pass


class ConfigurationError(PyenclaveError):
    """Raised when configuration is invalid."""
    pass


class UnsupportedPlatformError(PyenclaveError):
    """Raised when platform doesn't support required features."""
    pass

