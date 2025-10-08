"""
Tipos de resultado das execuções.
"""

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class ExecutionResult:
    exit_code: Optional[int] = None
    reason: Optional[str] = None  # "ok" | "timeout" | "oom" | "seccomp" | "landlock" | "signal"
    stdout: bytes = field(default_factory=bytes)
    stderr: bytes = field(default_factory=bytes)
    cpu_time_ms: Optional[int] = None
    peak_rss_kb: Optional[int] = None
    logs: List[str] = field(default_factory=list)
