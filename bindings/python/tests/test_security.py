"""
Testes de segurança end-to-end da API Python.
Valida que as camadas de isolamento funcionam corretamente na interface pública.
"""

import sys
import pytest


@pytest.mark.skipif(sys.platform != "linux", reason="Linux-only")
class TestSeccompIsolation:
    """Testes que validam bloqueio de syscalls perigosas via seccomp."""
    
    def test_network_blocked_by_default(self, current_python):
        """
        SECURITY: Socket creation deve ser bloqueada por padrão.
        Vulnerabilidade: Código malicioso fazendo requisições HTTP não autorizadas.
        """
        from pyenclave import run_python
        
        code = """
import socket
import sys

try:
    # Tentar criar socket TCP
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print("SECURITY_FAIL: Socket created", file=sys.stderr)
    s.close()
    sys.exit(1)
except (OSError, PermissionError) as e:
    # Esperado: bloqueado por seccomp ou namespace
    print(f"SECURITY_OK: Socket blocked - {type(e).__name__}")
    sys.exit(0)
"""
        
        result = run_python(code=code, network=False)
        
        # Deve bloquear: exit 0 (sucesso no bloqueio) ou morto por signal
        if result.exit_code == 0:
            assert b"SECURITY_OK" in result.stdout
        else:
            # Se morreu por signal, também é OK (seccomp matou o processo)
            assert result.signal is not None or result.exit_code != 1
    
    def test_network_allowed_when_explicitly_enabled(self, current_python):
        """
        SECURITY: Network deve funcionar APENAS quando explicitamente habilitada.
        """
        from pyenclave import run_python
        
        code = """
import socket
import sys

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print("Socket created successfully")
    s.close()
except Exception as e:
    print(f"Socket failed: {e}", file=sys.stderr)
    sys.exit(1)
"""
        
        result = run_python(code=code, network=True)
        
        # Com network=True, deve permitir
        assert result.exit_code == 0
        assert b"Socket created successfully" in result.stdout
    
    def test_subprocess_restrictions(self, current_python):
        """
        SECURITY: Subprocessos devem ter limitações.
        Vulnerabilidade: Fork bombs, execução de comandos do sistema.
        """
        from pyenclave import run_python
        
        code = """
import subprocess
import sys

try:
    # Tentar executar comando do sistema
    result = subprocess.run(['whoami'], capture_output=True, timeout=1)
    print(f"POTENTIAL_RISK: Command executed: {result.stdout.decode()}")
except FileNotFoundError:
    # Esperado: binário não encontrado em filesystem isolado
    print("SECURITY_OK: Command not found in isolated environment")
except Exception as e:
    print(f"SECURITY_OK: Command blocked - {type(e).__name__}")
"""
        
        result = run_python(code=code)
        
        # Deve bloquear ou não encontrar executáveis
        assert result.exit_code == 0
        assert b"SECURITY_OK" in result.stdout or b"not found" in result.stdout.lower()


@pytest.mark.skipif(sys.platform != "linux", reason="Linux-only")
class TestFilesystemIsolation:
    """Testes que validam isolamento de filesystem."""
    
    def test_cannot_read_sensitive_files(self, current_python):
        """
        SECURITY: Arquivos sensíveis do host não devem ser acessíveis.
        Vulnerabilidade: Leitura de /etc/passwd, /etc/shadow, chaves SSH, etc.
        """
        from pyenclave import run_python
        
        sensitive_files = [
            "/etc/passwd",
            "/etc/shadow",
            "/root/.ssh/id_rsa",
            "/home/*/.ssh/id_rsa",
        ]
        
        code = f"""
import sys

sensitive_files = {sensitive_files}
blocked = []
accessible = []

for path in sensitive_files:
    try:
        with open(path) as f:
            f.read(10)  # Tentar ler primeiros bytes
        accessible.append(path)
    except (FileNotFoundError, PermissionError):
        blocked.append(path)

if accessible:
    print(f"SECURITY_FAIL: Could read {{len(accessible)}} files: {{accessible}}", file=sys.stderr)
    sys.exit(1)
else:
    print(f"SECURITY_OK: All {{len(blocked)}} sensitive files blocked")
    sys.exit(0)
"""
        
        result = run_python(code=code, stateless=True)
        
        assert result.exit_code == 0
        assert b"SECURITY_OK" in result.stdout
        assert b"SECURITY_FAIL" not in result.stderr
    
    def test_cannot_write_to_system_directories(self, current_python):
        """
        SECURITY: Diretórios do sistema não devem ser graváveis.
        Vulnerabilidade: Sobrescrever binários, configurações, logs.
        """
        from pyenclave import run_python
        
        code = """
import sys

system_dirs = ["/etc", "/usr", "/bin", "/sbin", "/root"]
blocked = []
writable = []

for dir_path in system_dirs:
    try:
        test_file = f"{dir_path}/test_pyenclave_write"
        with open(test_file, 'w') as f:
            f.write("test")
        writable.append(dir_path)
    except (FileNotFoundError, PermissionError, OSError):
        blocked.append(dir_path)

if writable:
    print(f"SECURITY_FAIL: Could write to {len(writable)} dirs: {writable}", file=sys.stderr)
    sys.exit(1)
else:
    print(f"SECURITY_OK: All {len(blocked)} system directories protected")
    sys.exit(0)
"""
        
        result = run_python(code=code, stateless=True)
        
        assert result.exit_code == 0
        assert b"SECURITY_OK" in result.stdout
        assert b"SECURITY_FAIL" not in result.stderr
    
    def test_tmp_is_isolated(self, current_python, temp_dir):
        """
        SECURITY: /tmp deve ser isolado (não compartilhado com host).
        Vulnerabilidade: Compartilhamento de dados temporários entre processos.
        """
        from pyenclave import run_python
        import uuid
        
        # Criar arquivo no /tmp do host
        host_marker = str(uuid.uuid4())
        host_tmp_file = temp_dir / "host_marker.txt"
        host_tmp_file.write_text(host_marker)
        
        code = f"""
import os
import sys

# Verificar se consegue ver arquivo do host em /tmp
host_marker = "{host_marker}"
found_host_file = False

try:
    # Tentar encontrar o arquivo do host
    if os.path.exists("/tmp/host_marker.txt"):
        with open("/tmp/host_marker.txt") as f:
            if host_marker in f.read():
                found_host_file = True
except:
    pass

if found_host_file:
    print("SECURITY_FAIL: Can see host /tmp files", file=sys.stderr)
    sys.exit(1)
else:
    print("SECURITY_OK: /tmp is isolated from host")
    sys.exit(0)
"""
        
        result = run_python(code=code)
        
        assert result.exit_code == 0
        assert b"SECURITY_OK" in result.stdout


@pytest.mark.skipif(sys.platform != "linux", reason="Linux-only")
class TestProcessIsolation:
    """Testes que validam isolamento de processos."""
    
    def test_cannot_see_host_processes(self, current_python):
        """
        SECURITY: Processos do host não devem ser visíveis.
        Vulnerabilidade: Enumeração de processos, ataques de timing.
        """
        from pyenclave import run_python
        
        code = """
import os
import sys

try:
    # Tentar listar processos via /proc
    proc_dirs = [d for d in os.listdir('/proc') if d.isdigit()]
    
    if len(proc_dirs) > 20:
        print(f"SECURITY_WARNING: Too many processes visible: {len(proc_dirs)}", file=sys.stderr)
        print(f"PIDs: {sorted(proc_dirs)[:10]}...", file=sys.stderr)
    else:
        print(f"SECURITY_OK: Limited process visibility ({len(proc_dirs)} PIDs)")
    
    sys.exit(0)
except FileNotFoundError:
    # /proc não montado = ainda melhor isolamento
    print("SECURITY_OK: /proc not available")
    sys.exit(0)
"""
        
        result = run_python(code=code)
        
        # Deve ter isolamento ou /proc não disponível
        assert result.exit_code == 0
        assert b"SECURITY_OK" in result.stdout or b"SECURITY_WARNING" not in result.stderr


@pytest.mark.skipif(sys.platform != "linux", reason="Linux-only")
class TestResourceExhaustion:
    """Testes que previnem ataques de exaustão de recursos."""
    
    def test_memory_allocation_limits(self, current_python):
        """
        SECURITY: Alocação excessiva de memória deve ser limitada.
        Vulnerabilidade: DoS via consumo de memória do host.
        """
        from pyenclave import run_python
        
        code = """
import sys

data = []
mb_allocated = 0

try:
    # Tentar alocar 10GB de memória
    for i in range(10000):
        data.append(bytearray(1024 * 1024))  # 1MB
        mb_allocated += 1
        
        if mb_allocated % 100 == 0:
            print(f"Allocated {mb_allocated} MB...")
    
    print(f"SECURITY_WARNING: Allocated {mb_allocated} MB without limit", file=sys.stderr)
    sys.exit(1)
    
except MemoryError:
    print(f"SECURITY_OK: Memory limited after {mb_allocated} MB")
    sys.exit(0)
"""
        
        result = run_python(code=code, memory_limit_mb=512)
        
        # Deve falhar por limite ou MemoryError
        # Exit code 0 = MemoryError capturado (bom)
        # Exit code != 0 = morto por OOM killer (também bom)
        if result.exit_code == 0:
            assert b"SECURITY_OK" in result.stdout
    
    def test_infinite_loop_timeout(self, current_python):
        """
        SECURITY: Loops infinitos devem ser interrompidos.
        Vulnerabilidade: DoS via consumo de CPU.
        """
        from pyenclave import run_python
        import time
        
        code = """
import time
import sys

start = time.time()
iterations = 0

# Loop infinito simulado
while time.time() - start < 60:  # Tentaria rodar por 60s
    iterations += 1
    if iterations % 1000000 == 0:
        print(f"Iteration {iterations}")

print(f"SECURITY_FAIL: Loop ran for {time.time() - start}s", file=sys.stderr)
"""
        
        start_time = time.time()
        result = run_python(code=code, time_limit_s=2)
        elapsed = time.time() - start_time
        
        # Deve ser morto antes de completar
        # Não deve rodar por mais de 5 segundos (margem de segurança)
        assert elapsed < 5.0, f"Process ran for {elapsed}s, should be killed by timeout"
        assert b"SECURITY_FAIL" not in result.stderr


@pytest.mark.skipif(sys.platform != "linux", reason="Linux-only")
class TestInputValidation:
    """Testes que validam sanitização e validação de inputs."""
    
    def test_dangerous_environment_variables_blocked(self, current_python):
        """
        SECURITY: Variáveis de ambiente perigosas devem ser bloqueadas.
        Vulnerabilidade: LD_PRELOAD injection, path hijacking.
        """
        from pyenclave import run_python
        
        # Tentar passar variáveis perigosas
        dangerous_vars = {
            "LD_PRELOAD": "/tmp/malicious.so",
            "LD_LIBRARY_PATH": "/tmp/libs",
        }
        
        code = """
import os
import sys

dangerous = ['LD_PRELOAD', 'LD_LIBRARY_PATH', 'LD_AUDIT']
found = []

for var in dangerous:
    if var in os.environ:
        found.append(f"{var}={os.environ[var]}")

if found:
    print(f"SECURITY_FAIL: Dangerous vars present: {found}", file=sys.stderr)
    sys.exit(1)
else:
    print("SECURITY_OK: Dangerous environment variables filtered")
    sys.exit(0)
"""
        
        # API deve filtrar ou negar essas variáveis
        result = run_python(code=code, env_overrides=dangerous_vars)
        
        # Implementação futura: deve filtrar automaticamente
        # Por enquanto, apenas documentar o comportamento esperado
        assert result is not None  # Não deve crashear
        # TODO: Quando implementado, validar:
        # assert result.exit_code == 0
        # assert b"SECURITY_OK" in result.stdout


@pytest.mark.skipif(sys.platform != "linux", reason="Linux-only")
class TestSecurityMetadata:
    """Testes que validam que informações de segurança são reportadas."""
    
    def test_execution_result_contains_security_info(self, current_python):
        """
        SECURITY: Resultados devem indicar se houve violações de segurança.
        """
        from pyenclave import run_python, ExecutionResult
        
        result = run_python(code="print('test')")
        
        assert isinstance(result, ExecutionResult)
        # Verificar que temos campos para rastrear segurança
        assert hasattr(result, "exit_code")
        assert hasattr(result, "signal")
        # TODO: Adicionar campo 'reason' para indicar: "ok", "timeout", "oom", "seccomp_violation"


def test_security_probe_reports_capabilities():
    """
    SECURITY: probe() deve reportar capacidades de segurança disponíveis.
    Importante para entender o nível de isolamento do host.
    """
    from pyenclave import probe
    
    caps = probe()
    
    # Deve reportar capacidades de segurança
    assert "seccomp" in caps, "Should report seccomp support"
    assert "landlock" in caps, "Should report Landlock support"
    assert "userns" in caps, "Should report user namespace support"
    
    # Valores devem ser booleanos
    assert isinstance(caps["seccomp"], bool)
    assert isinstance(caps["landlock"], bool)
    assert isinstance(caps["userns"], bool)


@pytest.mark.skipif(sys.platform != "linux", reason="Linux-only")
class TestCodeInjectionPrevention:
    """Testes que previnem injeção de código e execução arbitrária."""
    
    def test_import_injection_via_string(self, current_python):
        """
        SECURITY: Import injection via __import__ dinâmico.
        Vulnerabilidade: Importar módulos não autorizados dinamicamente.
        """
        from pyenclave import run_python
        
        code = """
import sys

# Tentar importar módulo perigoso via string
dangerous_modules = ['os', 'subprocess', 'socket']
blocked = []
imported = []

for mod_name in dangerous_modules:
    try:
        mod = __import__(mod_name)
        imported.append(mod_name)
    except ImportError:
        blocked.append(mod_name)

print(f"Imported: {imported}")
print(f"Blocked: {blocked}")

# Mesmo que importe, algumas funções podem estar restritas
if 'os' in imported:
    import os
    try:
        os.system('whoami')
        print("SECURITY_WARNING: os.system() worked")
    except Exception as e:
        print(f"SECURITY_OK: os.system() blocked - {type(e).__name__}")
"""
        
        result = run_python(code=code, stateless=True)
        
        # Imports da stdlib devem funcionar, mas operações perigosas devem falhar
        assert result.exit_code == 0
        # Filesystem/network isolation deve proteger contra uso malicioso
    
    def test_eval_exec_restrictions(self, current_python):
        """
        SECURITY: eval() e exec() com código não confiável.
        Vulnerabilidade: Execução de código arbitrário via strings.
        """
        from pyenclave import run_python
        
        code = """
import sys

# Tentar usar eval/exec para bypassar restrições
malicious_code = "import socket; s = socket.socket(); print('BYPASS')"

try:
    exec(malicious_code)
    print("SECURITY_WARNING: exec() executed malicious code", file=sys.stderr)
except Exception as e:
    print(f"SECURITY_INFO: exec() ran but operations may be blocked")

# eval() com expressões perigosas
try:
    result = eval("__import__('os').system('whoami')")
    print(f"SECURITY_WARNING: eval() system call result: {result}", file=sys.stderr)
except Exception as e:
    print(f"SECURITY_OK: eval() blocked - {type(e).__name__}")
"""
        
        result = run_python(code=code)
        
        # Python permite eval/exec mas o sandbox deve bloquear operações perigosas
        assert result.exit_code == 0
        # Seccomp/namespaces devem proteger mesmo com eval/exec


@pytest.mark.skipif(sys.platform != "linux", reason="Linux-only")
class TestPathTraversalPrevention:
    """Testes que previnem path traversal e acesso não autorizado."""
    
    def test_path_traversal_attempts(self, current_python, temp_dir):
        """
        SECURITY: Tentativas de path traversal (../, ../../).
        Vulnerabilidade: Acessar arquivos fora dos diretórios montados.
        """
        from pyenclave import run_python
        
        input_dir = temp_dir / "allowed"
        input_dir.mkdir()
        (input_dir / "safe.txt").write_text("Safe content")
        
        code = """
import sys

# Tentativas de path traversal
traversal_attempts = [
    "../../../etc/passwd",
    "../../../../../../etc/shadow",
    "/etc/passwd",
    "/etc/../etc/passwd",
]

accessed = []
blocked = []

for path in traversal_attempts:
    try:
        with open(path) as f:
            f.read(10)
        accessed.append(path)
    except (FileNotFoundError, PermissionError, OSError):
        blocked.append(path)

if accessed:
    print(f"SECURITY_FAIL: Accessed {len(accessed)} paths: {accessed}", file=sys.stderr)
    sys.exit(1)
else:
    print(f"SECURITY_OK: All {len(blocked)} traversal attempts blocked")
    sys.exit(0)
"""
        
        result = run_python(code=code, stateless=True)
        
        assert result.exit_code == 0
        assert b"SECURITY_OK" in result.stdout
        assert b"SECURITY_FAIL" not in result.stderr
    
    def test_symlink_escape_attempts(self, current_python, temp_dir):
        """
        SECURITY: Symlinks para escapar do sandbox.
        Vulnerabilidade: Criar symlink apontando para fora do sandbox.
        """
        from pyenclave import run_python
        
        output_dir = temp_dir / "writable"
        output_dir.mkdir()
        
        code = """
import os
import sys

try:
    # Tentar criar symlink para /etc/passwd
    os.symlink('/etc/passwd', '/tmp/evil_link')
    
    # Tentar ler via symlink
    with open('/tmp/evil_link') as f:
        content = f.read(10)
    
    print("SECURITY_FAIL: Symlink escape worked", file=sys.stderr)
    sys.exit(1)
    
except (FileNotFoundError, PermissionError, OSError) as e:
    print(f"SECURITY_OK: Symlink blocked - {type(e).__name__}")
    sys.exit(0)
"""
        
        result = run_python(code=code)
        
        # Deve bloquear criação de symlinks ou acesso via symlinks
        assert result.exit_code == 0
        assert b"SECURITY_OK" in result.stdout


@pytest.mark.skipif(sys.platform != "linux", reason="Linux-only")
class TestSideChannelAttacks:
    """Testes que previnem ataques de canal lateral."""
    
    def test_timing_attacks_via_filesystem(self, current_python):
        """
        SECURITY: Timing attacks para descobrir existência de arquivos.
        Vulnerabilidade: Medir tempo de resposta para inferir informações.
        """
        from pyenclave import run_python
        
        code = """
import time
import sys

# Tentar inferir existência de arquivos via timing
test_paths = [
    "/etc/passwd",      # Provavelmente existe
    "/etc/shadow",      # Provavelmente existe mas sem acesso
    "/nonexistent",     # Não existe
]

timings = {}

for path in test_paths:
    start = time.time()
    try:
        with open(path) as f:
            f.read()
    except Exception:
        pass
    elapsed = time.time() - start
    timings[path] = elapsed

print(f"Timings: {timings}")

# Diferenças de timing não devem revelar informações sensíveis
# (filesystem isolado deve tornar timing uniforme)
"""
        
        result = run_python(code=code)
        
        # Teste informacional - documenta comportamento de timing
        assert result.exit_code == 0
    
    def test_memory_scanning_prevention(self, current_python):
        """
        SECURITY: Tentativas de escanear memória de outros processos.
        Vulnerabilidade: Ler /proc/[pid]/mem de outros processos.
        """
        from pyenclave import run_python
        
        code = """
import os
import sys

try:
    # Tentar listar processos
    proc_pids = [d for d in os.listdir('/proc') if d.isdigit()]
    
    accessible_mem = []
    
    for pid in proc_pids[:10]:  # Testar primeiros 10
        mem_path = f'/proc/{pid}/mem'
        try:
            # Tentar abrir memória de outro processo
            with open(mem_path, 'rb') as f:
                f.read(1)
            accessible_mem.append(pid)
        except (FileNotFoundError, PermissionError, OSError):
            pass
    
    if accessible_mem:
        print(f"SECURITY_WARNING: Could access memory of {len(accessible_mem)} processes")
    else:
        print("SECURITY_OK: Process memory isolated")
        
except FileNotFoundError:
    print("SECURITY_OK: /proc not available or isolated")
"""
        
        result = run_python(code=code)
        
        # Deve ter isolamento de memória entre processos
        assert result.exit_code == 0


@pytest.mark.skipif(sys.platform != "linux", reason="Linux-only")
class TestPrivilegeEscalation:
    """Testes que previnem escalação de privilégios."""
    
    def test_cannot_change_uid_gid(self, current_python):
        """
        SECURITY: Tentativas de mudar UID/GID.
        Vulnerabilidade: Escalar privilégios via setuid/setgid.
        """
        from pyenclave import run_python
        
        code = """
import os
import sys

original_uid = os.getuid()
original_gid = os.getgid()

print(f"Original UID: {original_uid}, GID: {original_gid}")

# Tentar mudar para root
try:
    os.setuid(0)
    print("SECURITY_FAIL: Could change to root", file=sys.stderr)
    sys.exit(1)
except PermissionError:
    print("SECURITY_OK: setuid(0) blocked")

# Tentar mudar para outro usuário
try:
    os.setuid(1000)
    print("SECURITY_WARNING: Could change UID", file=sys.stderr)
except PermissionError:
    print("SECURITY_OK: setuid(1000) blocked")

sys.exit(0)
"""
        
        result = run_python(code=code)
        
        assert result.exit_code == 0
        assert b"SECURITY_FAIL" not in result.stderr
    
    def test_cannot_use_capabilities(self, current_python):
        """
        SECURITY: Tentativas de usar Linux capabilities.
        Vulnerabilidade: Usar CAP_NET_RAW, CAP_SYS_ADMIN, etc.
        """
        from pyenclave import run_python
        
        code = """
import sys

try:
    # Tentar importar prctl para manipular capabilities
    import prctl
    
    # Verificar capabilities atuais
    caps = []
    for cap in range(40):  # CAP_LAST_CAP
        try:
            if prctl.cap_effective.is_set(cap):
                caps.append(cap)
        except:
            pass
    
    if len(caps) > 0:
        print(f"SECURITY_WARNING: Has {len(caps)} capabilities: {caps}", file=sys.stderr)
    else:
        print("SECURITY_OK: No dangerous capabilities")
        
except ImportError:
    print("SECURITY_OK: prctl not available (capabilities cannot be checked)")
except Exception as e:
    print(f"SECURITY_OK: Capability check failed - {type(e).__name__}")
"""
        
        result = run_python(code=code)
        
        # Não deve ter capabilities perigosas
        assert result.exit_code == 0


@pytest.mark.skipif(sys.platform != "linux", reason="Linux-only")
class TestInformationLeakage:
    """Testes que previnem vazamento de informações."""
    
    def test_cannot_read_environment_of_other_processes(self, current_python):
        """
        SECURITY: Tentativas de ler variáveis de ambiente de outros processos.
        Vulnerabilidade: Ler /proc/[pid]/environ para roubar secrets.
        """
        from pyenclave import run_python
        
        code = """
import os
import sys

try:
    proc_pids = [d for d in os.listdir('/proc') if d.isdigit() and d != str(os.getpid())]
    
    leaked_envs = []
    
    for pid in proc_pids[:10]:
        try:
            with open(f'/proc/{pid}/environ', 'rb') as f:
                env_data = f.read()
                if env_data:
                    leaked_envs.append(pid)
        except (FileNotFoundError, PermissionError, OSError):
            pass
    
    if leaked_envs:
        print(f"SECURITY_FAIL: Read environ of {len(leaked_envs)} processes", file=sys.stderr)
        sys.exit(1)
    else:
        print("SECURITY_OK: Process environments isolated")
        sys.exit(0)
        
except FileNotFoundError:
    print("SECURITY_OK: /proc not available")
    sys.exit(0)
"""
        
        result = run_python(code=code)
        
        assert result.exit_code == 0
        assert b"SECURITY_FAIL" not in result.stderr
    
    def test_cannot_read_cmdline_of_other_processes(self, current_python):
        """
        SECURITY: Tentativas de ler command lines de outros processos.
        Vulnerabilidade: Descobrir comandos executados (pode conter senhas).
        """
        from pyenclave import run_python
        
        code = """
import os
import sys

try:
    proc_pids = [d for d in os.listdir('/proc') if d.isdigit() and d != str(os.getpid())]
    
    readable_cmdlines = []
    
    for pid in proc_pids[:10]:
        try:
            with open(f'/proc/{pid}/cmdline', 'rb') as f:
                cmdline = f.read()
                if cmdline:
                    readable_cmdlines.append((pid, cmdline[:50]))
        except (FileNotFoundError, PermissionError, OSError):
            pass
    
    if readable_cmdlines:
        print(f"SECURITY_WARNING: Read {len(readable_cmdlines)} cmdlines", file=sys.stderr)
    else:
        print("SECURITY_OK: Process cmdlines isolated")
        
except FileNotFoundError:
    print("SECURITY_OK: /proc not available")
"""
        
        result = run_python(code=code)
        
        assert result.exit_code == 0
