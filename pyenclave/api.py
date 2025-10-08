"""
API de alto nível (UX). Constrói o RunSpec e delega ao núcleo em Rust (pyenclave._core).
"""

from typing import Any, Dict, List, Optional, Union
from . import env as _env
from . import mounts as _mounts
from . import policy as _policy
from . import probe as _probe
from .result import ExecutionResult

try:
    from . import _core  # extensão PyO3
except Exception:  # pragma: no cover
    _core = None  # stubs permitem importar sem compilar a extensão


def run_python(
    *,
    code: Optional[str] = None,
    script: Optional[str] = None,
    module: Optional[str] = None,
    args: Optional[List[str]] = None,
    interpreter: Union[str, bytes] = "3.12",  # rótulo ("3.12") ou path absoluto
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
    """
    Monta o RunSpec e chama o núcleo (`_core.run`).
    TODO: validar exclusividade de code/script/module, normalizar env (incluindo
    redirecionar caches/bytecode com `PYTHONPYCACHEPREFIX` para dentro do enclave),
    e aplicar defaults seguros compatíveis com o pipeline descrito no núcleo.
    """
    # TODO: montar spec (dict simples) e chamar _core.run(spec)
    # Retornar ExecutionResult a partir do payload do núcleo.
    return ExecutionResult()
    

def list_interpreters() -> list:
    """
    Descobre intérpretes (roots versionados e venvs/conda).
    """
    # TODO: delegar para env.discover_interpreters()
    return []


def probe() -> dict:
    """
    Checa capacidades do host (userns, seccomp, Landlock, cgroups).
    """
    # TODO: se _core disponível, chamar _core.py_probe()
    return {}
