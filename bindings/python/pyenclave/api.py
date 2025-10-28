"""
API de alto nível (UX). Constrói o RunSpec e delega ao núcleo em Rust (pyenclave._core).
"""

from typing import Any, Dict, List, Optional, Union
import sys
import os
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
    Executa código Python isolado em sandbox.
    
    Args:
        code: Código Python a executar (passado via -c)
        script: Caminho para script Python a executar
        module: Módulo Python a executar com -m
        args: Argumentos adicionais para o script/módulo
        interpreter: Rótulo de versão ("3.12") ou caminho absoluto do Python
        mounts: Dict com 'ro' e 'rw' listas de [src, dst]
        stateless: Se True, sem acesso ao filesystem do host
        network: Se True, permite acesso à rede (padrão: False)
        time_limit_s: Limite de tempo em segundos
        memory_limit_mb: Limite de memória em MB
        max_procs: Número máximo de processos
        fsize_mb: Tamanho máximo de arquivo em MB
        threads: Número de threads Python
        env_overrides: Variáveis de ambiente customizadas
    
    Returns:
        ExecutionResult com exit_code, stdout, stderr, etc.
    """
    if _core is None:
        raise RuntimeError("pyenclave._core extension not available - did you compile with maturin?")
    
    # Validar que apenas uma forma de execução foi especificada
    modes = sum([code is not None, script is not None, module is not None])
    if modes == 0:
        raise ValueError("Must specify one of: code, script, or module")
    if modes > 1:
        raise ValueError("Must specify only one of: code, script, or module")
    
    # Determinar caminho do intérprete
    if isinstance(interpreter, bytes):
        interpreter_path = interpreter.decode('utf-8')
    elif os.path.isabs(interpreter):
        interpreter_path = interpreter
    else:
        # Por enquanto, usar o Python atual
        # TODO: usar env.discover_interpreters() para resolver labels como "3.12"
        interpreter_path = sys.executable
    
    # Construir argv (SEM incluir o executável, pois o Rust adiciona automaticamente)
    argv_list = ["-I"]  # -I: modo isolado (sem site packages)
    
    if code is not None:
        argv_list.extend(["-c", code])
    elif script is not None:
        argv_list.append(script)
    elif module is not None:
        argv_list.extend(["-m", module])
    
    if args:
        argv_list.extend(args)
    
    # Construir mounts
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
    
    # Construir policy
    policy_spec = {
        "seccomp_profile": "default",
        "landlock": not network,  # Landlock se sem rede
        "network": network,
    }
    
    # Construir limits
    limits_spec = {}
    if time_limit_s is not None:
        limits_spec["time_limit_s"] = time_limit_s
    if memory_limit_mb is not None:
        limits_spec["memory_limit_mb"] = memory_limit_mb
    if max_procs is not None:
        limits_spec["max_procs"] = max_procs
    if fsize_mb is not None:
        limits_spec["fsize_mb"] = fsize_mb
    
    # Construir environment
    env_dict = {}
    
    # Variáveis padrão para Python isolado
    env_dict["PYTHONDONTWRITEBYTECODE"] = "1"
    env_dict["PYTHONUNBUFFERED"] = "1"
    env_dict["PYTHONHASHSEED"] = "0"
    
    if threads > 1:
        env_dict["OMP_NUM_THREADS"] = str(threads)
        env_dict["OPENBLAS_NUM_THREADS"] = str(threads)
    
    # Aplicar overrides
    if env_overrides:
        env_dict.update(env_overrides)
    
    # Construir RunSpec
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
    
    # Chamar núcleo Rust
    result_dict = _core.run(spec)
    
    # Converter para ExecutionResult
    return ExecutionResult(
        exit_code=result_dict.get("exit_code"),
        stdout=result_dict.get("stdout", b""),
        stderr=result_dict.get("stderr", b""),
        signal=result_dict.get("signal"),
    )


def list_interpreters() -> list:
    """
    Descobre intérpretes (roots versionados e venvs/conda).
    """
    # TODO: delegar para env.discover_interpreters()
    return []


def probe() -> dict:
    """
    Checa capacidades do host (userns, seccomp, Landlock, cgroups).
    
    Returns:
        dict com campos:
            - userns: bool
            - seccomp: bool
            - landlock: bool
            - landlock_abi: int ou None
            - cgroups_v2: bool
            - arch: str
            - kernel: str
    """
    if _core is None:
        raise RuntimeError("pyenclave._core extension not available - did you compile with maturin?")
    
    return _core.probe()

