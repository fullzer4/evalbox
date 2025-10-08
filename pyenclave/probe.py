"""
Sondagem de capacidades do host e relatório.
"""

from typing import Dict, Any


def probe_host() -> Dict[str, Any]:
    """
    Verifica userns, seccomp, Landlock (ABI), cgroups v2, kernel/arch.
    """
    # TODO: se houver _core, delegar; senão, retornar placeholders
    return {}
