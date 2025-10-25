from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class ExecutionResult:
    """Result of Python code execution in sandbox.

    Attributes:
        exit_code: Process exit code (0 for success, non-zero for failure)
        reason: Termination reason: "ok", "timeout", "oom", "seccomp", "landlock", "signal"
        stdout: Standard output captured as bytes
        stderr: Standard error captured as bytes
        signal: Signal number if process was terminated by signal
        cpu_time_ms: CPU time used in milliseconds
        peak_rss_kb: Peak resident set size in kilobytes
        logs: Additional log messages from sandbox runtime
    """

    exit_code: Optional[int] = None
    reason: Optional[str] = None
    stdout: bytes = field(default_factory=bytes)
    stderr: bytes = field(default_factory=bytes)
    signal: Optional[int] = None
    cpu_time_ms: Optional[int] = None
    peak_rss_kb: Optional[int] = None
    logs: List[str] = field(default_factory=list)

