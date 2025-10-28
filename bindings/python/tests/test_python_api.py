"""
Testes essenciais da API Python do pyenclave.
Foca nos testes que validam a interface pública e funcionalidade básica.
"""

import sys
import pytest


class TestImports:
    """Testes de importação e API pública."""
    
    def test_import_pyenclave(self):
        """Verifica que o pacote pode ser importado."""
        import pyenclave
        assert pyenclave is not None
    
    def test_version(self):
        """Verifica que a versão está definida."""
        import pyenclave
        assert hasattr(pyenclave, "__version__")
        assert isinstance(pyenclave.__version__, str)
    
    def test_api_exports(self):
        """Verifica que a API pública está exportada corretamente."""
        import pyenclave
        
        # Funções principais
        assert hasattr(pyenclave, "run_python")
        assert callable(pyenclave.run_python)
        
        assert hasattr(pyenclave, "probe")
        assert callable(pyenclave.probe)
        
        # Tipos
        assert hasattr(pyenclave, "ExecutionResult")
    
    def test_execution_result_structure(self):
        """Verifica a estrutura do ExecutionResult."""
        from pyenclave import ExecutionResult
        
        result = ExecutionResult()
        
        # Campos essenciais
        assert hasattr(result, "exit_code")
        assert hasattr(result, "stdout")
        assert hasattr(result, "stderr")
        assert hasattr(result, "signal")
        
        # Valores padrão
        assert result.exit_code is None
        assert result.stdout == b""
        assert result.stderr == b""
        assert result.signal is None


@pytest.mark.skipif(sys.platform != "linux", reason="Linux-only")
class TestProbe:
    """Testes da função probe()."""
    
    def test_probe_returns_dict(self):
        """Verifica que probe() retorna um dicionário."""
        from pyenclave import probe
        
        result = probe()
        assert isinstance(result, dict)
    
    def test_probe_structure(self):
        """Verifica estrutura do resultado de probe()."""
        from pyenclave import probe
        
        result = probe()
        
        # Campos esperados
        assert "userns" in result
        assert "seccomp" in result
        assert "landlock" in result
        assert "arch" in result
        assert "kernel" in result
        
        # Tipos corretos
        assert isinstance(result["userns"], bool)
        assert isinstance(result["seccomp"], bool)
        assert isinstance(result["landlock"], bool)
        assert isinstance(result["arch"], str)
        if result.get("kernel"):
            assert isinstance(result["kernel"], str)


@pytest.mark.skipif(sys.platform != "linux", reason="Linux-only")
class TestBasicExecution:
    """Testes básicos de execução de código Python."""
    
    def test_run_simple_print(self, current_python):
        """Testa execução básica de print."""
        from pyenclave import run_python
        
        result = run_python(code="print('hello world')")
        
        assert result.exit_code == 0
        assert b"hello world" in result.stdout
        assert result.stderr == b""
    
    def test_run_with_stderr(self, current_python):
        """Testa captura de stderr."""
        from pyenclave import run_python
        
        code = """
import sys
print("stdout message")
print("stderr message", file=sys.stderr)
"""
        
        result = run_python(code=code)
        
        assert result.exit_code == 0
        assert b"stdout message" in result.stdout
        assert b"stderr message" in result.stderr
    
    def test_run_with_exit_code(self, current_python):
        """Testa captura de exit code não-zero."""
        from pyenclave import run_python
        
        result = run_python(code="import sys; sys.exit(42)")
        
        assert result.exit_code == 42
    
    def test_run_with_exception(self, current_python):
        """Testa captura de exceção Python."""
        from pyenclave import run_python
        
        result = run_python(code="raise ValueError('test error')")
        
        assert result.exit_code != 0
        assert b"ValueError" in result.stderr
        assert b"test error" in result.stderr
    
    def test_run_with_imports(self, current_python):
        """Testa que imports da stdlib funcionam."""
        from pyenclave import run_python
        
        code = """
import sys
import json
import math

print(f"Python {sys.version_info.major}.{sys.version_info.minor}")
print(f"json: {json.dumps({'ok': True})}")
print(f"math.pi: {math.pi:.2f}")
"""
        
        result = run_python(code=code)
        
        assert result.exit_code == 0
        assert b"Python" in result.stdout
        assert b'"ok": true' in result.stdout
        assert b"3.14" in result.stdout
    
    def test_exclusive_code_script_module(self, current_python):
        """Verifica que apenas um de code/script/module pode ser especificado."""
        from pyenclave import run_python
        
        with pytest.raises(ValueError, match="only one"):
            run_python(code="print('a')", script="/tmp/b.py")
        
        with pytest.raises(ValueError, match="only one"):
            run_python(code="print('a')", module="json.tool")
        
        with pytest.raises(ValueError, match="only one"):
            run_python(script="/tmp/a.py", module="json.tool")
    
    def test_must_specify_one_mode(self, current_python):
        """Verifica que pelo menos um modo deve ser especificado."""
        from pyenclave import run_python
        
        with pytest.raises(ValueError, match="Must specify one"):
            run_python()


@pytest.mark.skipif(sys.platform != "linux", reason="Linux-only")
class TestScriptExecution:
    """Testes de execução de scripts."""
    
    def test_run_script_file(self, current_python, sample_script):
        """Testa execução de arquivo script."""
        from pyenclave import run_python
        
        result = run_python(script=str(sample_script))
        
        assert result.exit_code == 0
        assert b"Hello from script!" in result.stdout
    
    def test_run_script_with_args(self, current_python, temp_dir):
        """Testa execução de script com argumentos."""
        from pyenclave import run_python
        
        script = temp_dir / "args.py"
        script.write_text("""
import sys
print(f"Args: {sys.argv[1:]}")
""")
        
        result = run_python(
            script=str(script),
            args=["arg1", "arg2", "arg3"]
        )
        
        assert result.exit_code == 0
        assert b"arg1" in result.stdout
        assert b"arg2" in result.stdout
        assert b"arg3" in result.stdout


@pytest.mark.skipif(sys.platform != "linux", reason="Linux-only")
class TestMounts:
    """Testes de montagem de filesystem."""
    
    @pytest.mark.skip(reason="Mounts ainda não implementados no pipeline completo")
    def test_read_from_ro_mount(self, current_python, temp_dir):
        """Testa leitura de mount read-only."""
        from pyenclave import run_python
        
        # Criar arquivo de entrada
        input_dir = temp_dir / "inputs"
        input_dir.mkdir()
        input_file = input_dir / "data.txt"
        input_file.write_text("Sample data\n")
        
        code = """
with open('/inputs/data.txt') as f:
    content = f.read()
    print(f"Read: {content.strip()}")
"""
        
        result = run_python(
            code=code,
            mounts={"ro": [[str(input_dir), "/inputs"]]}
        )
        
        assert result.exit_code == 0
        assert b"Sample data" in result.stdout
    
    @pytest.mark.skip(reason="Mounts ainda não implementados no pipeline completo")
    def test_write_to_rw_mount(self, current_python, temp_dir):
        """Testa escrita em mount read-write."""
        from pyenclave import run_python
        
        output_dir = temp_dir / "outputs"
        output_dir.mkdir()
        
        code = """
with open('/outputs/result.txt', 'w') as f:
    f.write("Success!\\n")
print("File written")
"""
        
        result = run_python(
            code=code,
            mounts={"rw": [[str(output_dir), "/outputs"]]}
        )
        
        assert result.exit_code == 0
        assert b"File written" in result.stdout
        
        # Verificar que o arquivo foi criado no host
        output_file = output_dir / "result.txt"
        assert output_file.exists()
        assert "Success!" in output_file.read_text()


@pytest.mark.skipif(sys.platform != "linux", reason="Linux-only")
class TestEnvironment:
    """Testes de variáveis de ambiente."""
    
    def test_custom_env_vars(self, current_python):
        """Testa passagem de variáveis de ambiente customizadas."""
        from pyenclave import run_python
        
        code = """
import os
print(f"CUSTOM_VAR: {os.environ.get('CUSTOM_VAR', 'NOT_SET')}")
print(f"ANOTHER_VAR: {os.environ.get('ANOTHER_VAR', 'NOT_SET')}")
"""
        
        result = run_python(
            code=code,
            env_overrides={
                "CUSTOM_VAR": "custom_value",
                "ANOTHER_VAR": "another_value"
            }
        )
        
        assert result.exit_code == 0
        assert b"CUSTOM_VAR: custom_value" in result.stdout
        assert b"ANOTHER_VAR: another_value" in result.stdout
    
    def test_python_isolated_mode(self, current_python):
        """Verifica que Python roda em modo isolado (-I)."""
        from pyenclave import run_python
        
        code = """
import sys
print(f"isolated: {sys.flags.isolated}")
print(f"dont_write_bytecode: {sys.flags.dont_write_bytecode}")
"""
        
        result = run_python(code=code)
        
        assert result.exit_code == 0
        # Flag -I ativa isolated mode
        assert b"isolated: 1" in result.stdout or b"isolated: True" in result.stdout


@pytest.mark.skipif(sys.platform != "linux", reason="Linux-only")  
class TestErrorHandling:
    """Testes de tratamento de erros."""
    
    def test_syntax_error(self, current_python):
        """Testa captura de erro de sintaxe."""
        from pyenclave import run_python
        
        result = run_python(code="print('missing quote)")
        
        assert result.exit_code != 0
        assert b"SyntaxError" in result.stderr
    
    def test_runtime_error(self, current_python):
        """Testa captura de erro em runtime."""
        from pyenclave import run_python
        
        result = run_python(code="undefined_variable")
        
        assert result.exit_code != 0
        assert b"NameError" in result.stderr
    
    def test_division_by_zero(self, current_python):
        """Testa captura de ZeroDivisionError."""
        from pyenclave import run_python
        
        result = run_python(code="x = 1 / 0")
        
        assert result.exit_code != 0
        assert b"ZeroDivisionError" in result.stderr
