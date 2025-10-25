class PyenclaveError(Exception):
    """Base exception for all pyenclave errors."""


class SecurityError(PyenclaveError):
    """Base exception for security-related failures."""


class PreflightError(PyenclaveError):
    """Raised when system capability checks fail during probe."""


class PolicyError(SecurityError):
    """Raised when security policy configuration is invalid or cannot be applied."""


class MountError(PyenclaveError):
    """Raised when filesystem mount configuration is invalid."""


class TimeoutError(SecurityError):
    """Raised when execution exceeds configured time limit."""


class ResourceLimitError(SecurityError):
    """Raised when resource limits are exceeded (memory, processes, etc)."""


class IsolationError(SecurityError):
    """Raised when isolation setup fails (namespaces, seccomp, landlock)."""


class ExecutionError(PyenclaveError):
    """Raised when code execution fails unexpectedly."""


class ConfigurationError(PyenclaveError):
    """Raised when user-provided configuration is invalid."""


class UnsupportedPlatformError(PyenclaveError):
    """Raised when platform doesn't support required security features."""

