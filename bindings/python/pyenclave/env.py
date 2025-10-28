"""
Descoberta e resolução de intérpretes (labels → /opt/pyroots/X.Y ou path de venv/conda).
"""

from typing import Dict, Any, List, Optional


def resolve_interpreter(label_or_path: str) -> Dict[str, Any]:
    """
    Retorna um objeto InterpreterInfo (dict) padronizado.
    Ex.: {"label": "3.12", "path": "/opt/pyroots/3.12/bin/python3.12"}
    """
    # TODO: detectar se é label semântico ou path
    return {}


def discover_interpreters() -> List[Dict[str, Any]]:
    """
    Varre locais comuns para CPython/pyenv/conda/venvs e roots internos.
    """
    # TODO: implementar varredura
    return []
