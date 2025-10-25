"""
Validação e plano de mounts (RO/RW), raiz efêmera e pontos internos (/inputs, /output, /state).
"""

from typing import Dict, Any


def build_mount_plan(mounts: Dict[str, list], stateless: bool = True) -> Dict[str, Any]:
    """
    Normaliza e valida um MountPlan.
    Esperado: {"ro": ["host_a:/inputs", ...], "rw": ["host_b:/output", ...]}
    """
    # TODO: normalizar caminhos, reservar /inputs, /output, /state, verificar conflitos
    return {}


def validate_mounts(plan: Dict[str, Any]) -> None:
    """
    Levanta exceção se houver colisões, caminhos inválidos ou destinos proibidos.
    """
    # TODO
    return None
