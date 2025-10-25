"""
Seleção de perfis de política e derivação de Landlock a partir dos mounts.
"""

from typing import Dict, Any


def select_seccomp_profile(target_arch: str, mode: str = "python-min") -> Dict[str, Any]:
    """
    Retorna metadados de perfil seccomp (ex.: id, path do BPF embedado).
    """
    # TODO: selecionar assets por arquitetura e modo
    return {}


def derive_landlock_rules(plan: Dict[str, Any]) -> Dict[str, Any]:
    """
    Gera allowlist de leitura/escrita conforme binds RO/RW.
    """
    # TODO
    return {}
