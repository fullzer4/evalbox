import os
import sys
from typing import Dict, List, Optional, Union

from .exceptions import ConfigurationError
from .result import ExecutionResult

try:
    from . import _core
except ImportError:  # pragma: no cover
    _core = None


def run_python(
    *,
    code: Optional[str] = None,
    script: Optional[str] = None,
    module: Optional[str] = None,
    args: Optional[List[str]] = None,
    interpreter: Union[str, bytes] = "3.12",
    mounts: Optional[Dict[str, List[str]]] = None,
    stateless: bool = True,
    network: bool = False,
    time_limit_s: Optional[int] = None,
    memory_limit_mb: Optional[int] = None,
    max_procs: Optional[int] = None,
    fsize_mb: Optional[int] = None,
    threads: int = 1,
    env_overrides: Optional[Dict[str, str]] = None,
) -> ExecutionResult:
    """Execute Python code in an isolated sandbox.

    Args:
        code: Python code to execute (via -c flag)
        script: Path to Python script file
        module: Python module to run (via -m flag)
        args: Additional arguments for script/module
        interpreter: Version label ("3.12") or absolute path to Python binary
        mounts: Mount specification dict with 'ro' and 'rw' lists
        stateless: If True, no host filesystem access (default: True)
        network: If True, allow network access (default: False)
        time_limit_s: Maximum execution time in seconds
        memory_limit_mb: Maximum memory usage in MB
        max_procs: Maximum number of processes
        fsize_mb: Maximum file size in MB
        threads: Number of Python threads
        env_overrides: Custom environment variables

    Returns:
        ExecutionResult with exit_code, stdout, stderr, and metadata

    Raises:
        ConfigurationError: If configuration is invalid
        RuntimeError: If core extension is not available
    """
    if _core is None:
        raise RuntimeError(
            "pyenclave._core extension not available. "
            "Compile with: maturin develop"
        )

    _validate_execution_mode(code, script, module)

    interpreter_path = _resolve_interpreter(interpreter)
    argv_list = _build_argv(code, script, module, args)
    mounts_spec = _build_mounts_spec(mounts)
    policy_spec = _build_policy_spec(network)
    limits_spec = _build_limits_spec(
        time_limit_s, memory_limit_mb, max_procs, fsize_mb
    )
    env_dict = _build_env_dict(threads, env_overrides)

    spec = {
        "interpreter": {
            "label": None,
            "path": interpreter_path,
        },
        "argv": argv_list,
        "mounts": mounts_spec,
        "policy": policy_spec,
        "limits": limits_spec,
        "cwd": None,
        "umask": None,
        "env": env_dict,
    }

    result_dict = _core.run(spec)

    return ExecutionResult(
        exit_code=result_dict.get("exit_code"),
        stdout=result_dict.get("stdout", b""),
        stderr=result_dict.get("stderr", b""),
        signal=result_dict.get("signal"),
    )


def list_interpreters() -> List[Dict[str, str]]:
    """Discover available Python interpreters.

    Scans common locations for Python installations including:
    - System Python installations
    - pyenv versions
    - Conda environments
    - Virtual environments

    Returns:
        List of interpreter info dicts with 'label' and 'path' keys

    Note:
        Currently returns empty list. Full discovery implementation pending.
    """
    # TODO: Implement env.discover_interpreters()
    return []


def probe() -> Dict[str, any]:
    """Check host system capabilities for sandboxing.

    Returns:
        Dict with capability flags:
            - userns: bool - User namespace support
            - seccomp: bool - Seccomp-BPF support
            - landlock: bool - Landlock LSM support
            - landlock_abi: Optional[int] - Landlock ABI version
            - cgroups_v2: bool - Cgroups v2 support
            - arch: str - System architecture
            - kernel: str - Kernel version

    Raises:
        RuntimeError: If core extension is not available
    """
    if _core is None:
        raise RuntimeError(
            "pyenclave._core extension not available. "
            "Compile with: maturin develop"
        )

    return _core.probe()


# Internal helper functions


def _validate_execution_mode(
    code: Optional[str],
    script: Optional[str],
    module: Optional[str],
) -> None:
    """Validate that exactly one execution mode is specified."""
    modes = sum([code is not None, script is not None, module is not None])
    if modes == 0:
        raise ConfigurationError(
            "Must specify one of: code, script, or module"
        )
    if modes > 1:
        raise ConfigurationError(
            "Must specify only one of: code, script, or module"
        )


def _resolve_interpreter(interpreter: Union[str, bytes]) -> str:
    """Resolve interpreter label or path to absolute path."""
    if isinstance(interpreter, bytes):
        interpreter_path = interpreter.decode("utf-8")
    elif os.path.isabs(interpreter):
        interpreter_path = interpreter
    else:
        # TODO: Use env.discover_interpreters() to resolve labels like "3.12"
        interpreter_path = sys.executable

    return interpreter_path


def _build_argv(
    code: Optional[str],
    script: Optional[str],
    module: Optional[str],
    args: Optional[List[str]],
) -> List[str]:
    """Build command-line arguments for Python execution."""
    argv_list = ["-I"]  # Isolated mode (no site packages)

    if code is not None:
        argv_list.extend(["-c", code])
    elif script is not None:
        argv_list.append(script)
    elif module is not None:
        argv_list.extend(["-m", module])

    if args:
        argv_list.extend(args)

    return argv_list


def _build_mounts_spec(mounts: Optional[Dict[str, List[str]]]) -> Dict[str, any]:
    """Build mount specification for filesystem access."""
    mounts_spec = {
        "ro": [],
        "rw": [],
        "ephemeral_tmp": True,
    }

    if mounts:
        if "ro" in mounts:
            mounts_spec["ro"] = mounts["ro"]
        if "rw" in mounts:
            mounts_spec["rw"] = mounts["rw"]

    return mounts_spec


def _build_policy_spec(network: bool) -> Dict[str, any]:
    """Build security policy specification."""
    return {
        "seccomp_profile": "default",
        "landlock": not network,
        "network": network,
    }


def _build_limits_spec(
    time_limit_s: Optional[int],
    memory_limit_mb: Optional[int],
    max_procs: Optional[int],
    fsize_mb: Optional[int],
) -> Dict[str, int]:
    """Build resource limits specification."""
    limits_spec = {}

    if time_limit_s is not None:
        limits_spec["time_limit_s"] = time_limit_s
    if memory_limit_mb is not None:
        limits_spec["memory_limit_mb"] = memory_limit_mb
    if max_procs is not None:
        limits_spec["max_procs"] = max_procs
    if fsize_mb is not None:
        limits_spec["fsize_mb"] = fsize_mb

    return limits_spec


def _build_env_dict(
    threads: int,
    env_overrides: Optional[Dict[str, str]],
) -> Dict[str, str]:
    """Build environment variables dict."""
    env_dict = {
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONUNBUFFERED": "1",
        "PYTHONHASHSEED": "0",
    }

    if threads > 1:
        env_dict["OMP_NUM_THREADS"] = str(threads)
        env_dict["OPENBLAS_NUM_THREADS"] = str(threads)

    if env_overrides:
        env_dict.update(env_overrides)

    return env_dict

