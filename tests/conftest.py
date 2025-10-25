"""
Configuração de fixtures e helpers para testes do pyenclave.
"""

import os
import sys
import tempfile
import pytest
from pathlib import Path


@pytest.fixture
def temp_dir():
    """Cria um diretório temporário para testes."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def sample_script(temp_dir):
    """Cria um script Python de exemplo para testes."""
    script = temp_dir / "test_script.py"
    script.write_text("print('Hello from script!')\n")
    return script


@pytest.fixture
def sample_data_file(temp_dir):
    """Cria um arquivo de dados de exemplo."""
    data_file = temp_dir / "input_data.txt"
    data_file.write_text("Sample input data\n")
    return data_file


@pytest.fixture
def current_python():
    """Retorna o caminho do Python atual."""
    return sys.executable


@pytest.fixture
def python_version():
    """Retorna a versão do Python atual (ex: '3.12')."""
    return f"{sys.version_info.major}.{sys.version_info.minor}"


def requires_linux():
    """Decorator para pular testes que requerem Linux."""
    return pytest.mark.skipif(
        sys.platform != "linux",
        reason="Requires Linux"
    )


def requires_root():
    """Decorator para pular testes que requerem root (ou user namespaces)."""
    return pytest.mark.skipif(
        os.geteuid() != 0 and not can_create_user_namespace(),
        reason="Requires root or unprivileged user namespaces"
    )


def can_create_user_namespace():
    """
    Verifica se o sistema permite criar user namespaces sem privilégios.
    """
    try:
        # Tenta ler a configuração do kernel
        with open("/proc/sys/kernel/unprivileged_userns_clone", "r") as f:
            return f.read().strip() == "1"
    except FileNotFoundError:
        # Se o arquivo não existe, assume que é permitido (kernel antigo ou permite por padrão)
        return True
    except Exception:
        return False


@pytest.fixture
def skip_if_no_userns():
    """Fixture que pula o teste se user namespaces não estiverem disponíveis."""
    if not can_create_user_namespace() and os.geteuid() != 0:
        pytest.skip("User namespaces not available")


def is_linux():
    """Verifica se está rodando em Linux."""
    return sys.platform == "linux"
