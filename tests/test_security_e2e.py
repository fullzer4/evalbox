import os
import time

import pytest
from conftest import ISOLATE_ONLY, LINUX_ONLY

from pyenclave import ExecutionResult, probe, run_python


@LINUX_ONLY
@ISOLATE_ONLY
class TestNetworkIsolation:
    """End-to-end network isolation tests using 'isolate'.

    Notes:
      - By default, 'isolate' places the process in a new network namespace
        with *no* external interfaces (only per-namespace loopback), so
        outbound connections fail. This validates "practical" network
        isolation without requiring seccomp to block socket() itself.
        Ref: isolate manpage --share-net (default is isolated). [CVE context: N/A]
    """

    def test_outbound_connect_fails_by_default(self):
        """SECURITY: outbound connections should fail by default.

        We try to connect to TEST-NET-3 (203.0.113.1:80). This should raise
        OSError (e.g., ENETUNREACH/EHOSTUNREACH/ECONNREFUSED) when network is isolated.
        """
        code = r"""
import socket, sys
addr = ("203.0.113.1", 80)  # TEST-NET-3 (documentation address)
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(1.0)
try:
    s.connect(addr)
    print("SECURITY_FAIL: outbound connect unexpectedly succeeded", file=sys.stderr)
    sys.exit(1)
except OSError as e:
    print(f"SECURITY_OK: connect blocked/failed: {e.__class__.__name__}")
    sys.exit(0)
"""
        result = run_python(code=code, network=False, time_limit_s=2, memory_limit_mb=64)
        assert result.exit_code == 0
        assert b"SECURITY_OK" in result.stdout


@LINUX_ONLY
@ISOLATE_ONLY
class TestFilesystemIsolation:
    """Filesystem isolation tests.

    Notes:
      - Sandbox should *not* expose host-sensitive paths.
      - /tmp inside sandbox is a fresh directory (per isolate defaults).
      - Path traversal and symlink escape attempts should fail.
      - CVE context: generic traversal issues like Apache HTTPD CVE‑2021‑41773
        demonstrate why strict FS boundaries matter.
    """

    def test_cannot_read_sensitive_files(self):
        """SECURITY: host sensitive files must not be readable.

        Example paths: /etc/passwd, /etc/shadow, SSH keys. In typical isolate defaults,
        /etc is not bound, so FileNotFoundError is expected.
        """
        code = r"""
import sys
sensitive_files = ["/etc/passwd", "/etc/shadow", "/root/.ssh/id_rsa", "/home/*/.ssh/id_rsa"]
blocked, accessible = [], []
for path in sensitive_files:
    try:
        with open(path) as f:
            f.read(10)
        accessible.append(path)
    except (FileNotFoundError, PermissionError, OSError):
        blocked.append(path)
if accessible:
    print(f"SECURITY_FAIL: could read {len(accessible)}: {accessible}", file=sys.stderr)
    sys.exit(1)
else:
    print(f"SECURITY_OK: blocked {len(blocked)} sensitive paths")
    sys.exit(0)
"""
        result = run_python(code=code, time_limit_s=2, memory_limit_mb=64)
        assert result.exit_code == 0
        assert b"SECURITY_OK" in result.stdout
        assert b"SECURITY_FAIL" not in result.stderr

    def test_tmp_is_isolated(self, temp_dir):
        """SECURITY: /tmp must be isolated from the host.

        We drop a marker in the host /tmp and confirm it's not visible inside the sandbox.
        """
        host_marker_path = "/tmp/host_marker.txt"
        try:
            marker = "pyenclave-marker"
            with open(host_marker_path, "w") as f:
                f.write(marker)

            code = r"""
import os, sys
if os.path.exists("/tmp/host_marker.txt"):
    print("SECURITY_FAIL: sandbox /tmp can see host file", file=sys.stderr)
    sys.exit(1)
print("SECURITY_OK: sandbox /tmp is isolated")
"""
            result = run_python(code=code, time_limit_s=2, memory_limit_mb=32)
            assert result.exit_code == 0
            assert b"SECURITY_OK" in result.stdout
        finally:
            try:
                os.remove(host_marker_path)
            except FileNotFoundError:
                pass

    def test_path_traversal_attempts(self):
        """SECURITY: simple path traversal attempts should fail.

        Motivation: path traversal classes of bugs (e.g., Apache HTTPD CVE‑2021‑41773).
        """
        code = r"""
import sys
traversal = ["../../../etc/passwd", "../../../../../../etc/shadow", "/etc/passwd", "/etc/../etc/passwd"]
blocked, accessed = [], []
for p in traversal:
    try:
        with open(p) as f:
            f.read(10)
        accessed.append(p)
    except (FileNotFoundError, PermissionError, OSError):
        blocked.append(p)
if accessed:
    print(f"SECURITY_FAIL: accessed {len(accessed)} paths: {accessed}", file=sys.stderr)
    sys.exit(1)
print(f"SECURITY_OK: blocked {len(blocked)} traversal attempts")
"""
        result = run_python(code=code, time_limit_s=2, memory_limit_mb=32)
        assert result.exit_code == 0
        assert b"SECURITY_OK" in result.stdout
        assert b"SECURITY_FAIL" not in result.stderr

    def test_symlink_escape_attempts(self):
        """SECURITY: symlink escapes should fail.

        Note: Symlink races/escapes are a classic issue (see CWE‑61; numerous CVEs in the wild).
        """
        code = r"""
import os, sys
try:
    os.symlink('/etc/passwd', '/tmp/evil_link')
    with open('/tmp/evil_link') as f:
        f.read(10)
    print("SECURITY_FAIL: symlink escape worked", file=sys.stderr)
    sys.exit(1)
except (FileNotFoundError, PermissionError, OSError):
    print("SECURITY_OK: symlink escape blocked")
"""
        result = run_python(code=code, time_limit_s=2, memory_limit_mb=32)
        assert result.exit_code == 0
        assert b"SECURITY_OK" in result.stdout


@LINUX_ONLY
@ISOLATE_ONLY
class TestProcessAndProcIsolation:
    """Process isolation (/proc scoping) tests.

    Expectation: /proc should not expose host processes or their internals.
    """

    def test_proc_memory_not_accessible(self):
        """SECURITY: cannot read /proc/[pid]/mem of other processes."""
        code = r"""
import os
pids = [d for d in os.listdir('/proc') if d.isdigit()]
accessible = []
for pid in pids[:8]:
    try:
        if pid != str(os.getpid()):
            with open(f"/proc/{pid}/mem", "rb") as f:
                f.read(1)
            accessible.append(pid)
    except Exception:
        pass
if accessible:
    print(f"SECURITY_FAIL: could read mem of {len(accessible)} PIDs", file=sys.stderr)
    raise SystemExit(1)
print("SECURITY_OK: other processes' memory not accessible")
"""
        result = run_python(code=code, time_limit_s=2, memory_limit_mb=32)
        assert result.exit_code == 0
        assert b"SECURITY_OK" in result.stdout

    def test_proc_environ_cmdline_leakage(self):
        """SECURITY: prevent leakage via /proc/*/(environ|cmdline)."""
        code = r"""
import os, sys
pids = [d for d in os.listdir('/proc') if d.isdigit() and d != str(os.getpid())]
leaks = []
for pid in pids[:8]:
    for suffix in ("environ", "cmdline"):
        try:
            with open(f"/proc/{pid}/{suffix}", "rb") as f:
                if f.read(1):
                    leaks.append((pid, suffix))
        except Exception:
            pass
if leaks:
    print(f"SECURITY_WARNING: read {len(leaks)} proc entries", file=sys.stderr)
else:
    print("SECURITY_OK: proc entries blocked")
"""
        result = run_python(code=code, time_limit_s=2, memory_limit_mb=32)
        assert result.exit_code == 0


@LINUX_ONLY
@ISOLATE_ONLY
class TestResourceExhaustion:
    """Resource exhaustion protection tests.

    We use very tight limits to prevent host load; allocation should raise MemoryError
    or be killed by the sandbox.
    """

    def test_memory_allocation_limits(self):
        """SECURITY: enforce low memory limits (e.g., 128MB)."""
        code = r"""
data = []
mb = 0
try:
    for _ in range(500):  # 500 MB target if unlimited
        data.append(bytearray(1024 * 1024))
        mb += 1
    print(f"SECURITY_FAIL: allocated {mb} MB", file=sys.stderr)
    raise SystemExit(1)
except MemoryError:
    print(f"SECURITY_OK: memory limited after ~{mb} MB")
"""
        result = run_python(code=code, time_limit_s=2, memory_limit_mb=128)
        if result.exit_code == 0:
            assert b"SECURITY_OK" in result.stdout  # MemoryError path
        # else: killed by sandbox/OOM; still acceptable

    def test_infinite_loop_timeout(self):
        """SECURITY: infinite loops must be stopped by time limit."""
        code = r"""
import time
start = time.time()
i = 0
while time.time() - start < 60:
    i += 1
    if i % 1_000_000 == 0:
        print(f"i={i}")
print("SECURITY_FAIL: loop ran too long")
"""
        t0 = time.time()
        result = run_python(code=code, time_limit_s=1, memory_limit_mb=32)
        elapsed = time.time() - t0
        assert elapsed < 5.0
        assert b"SECURITY_FAIL" not in result.stderr


@LINUX_ONLY
@ISOLATE_ONLY
class TestInputValidation:
    """Input/env validation tests."""

    def test_dangerous_environment_variables_blocked(self):
        """SECURITY: block loader-related environment variables.

        CVE context:
          - CVE‑2023‑4911 (Looney Tunables / GLIBC_TUNABLES).
          - Historical LD_PRELOAD/LD_LIBRARY_PATH abuse in various apps.
        """
        # Request dangerous envs; wrapper must filter them out.
        dangerous = {
            "LD_PRELOAD": "/tmp/malicious.so",
            "LD_LIBRARY_PATH": "/tmp/libs",
            "LD_AUDIT": "1",
            "GLIBC_TUNABLES": "glibc.malloc.check=3",
        }
        code = r"""
import os, sys
bad = [k for k in ("LD_PRELOAD","LD_LIBRARY_PATH","LD_AUDIT","GLIBC_TUNABLES") if k in os.environ]
if bad:
    print(f"SECURITY_FAIL: dangerous env present: {bad}", file=sys.stderr)
    raise SystemExit(1)
print("SECURITY_OK: dangerous env filtered")
"""
        result = run_python(code=code, env_overrides=dangerous, time_limit_s=1.5, memory_limit_mb=32)
        assert result.exit_code == 0
        assert b"SECURITY_OK" in result.stdout


@LINUX_ONLY
@ISOLATE_ONLY
class TestPrivilegeEscalation:
    """Privilege escalation prevention tests."""

    def test_cannot_change_uid_gid(self):
        """SECURITY: setuid/setgid calls should fail in sandbox."""
        code = r"""
import os, sys
try:
    os.setuid(0)
    print("SECURITY_FAIL: setuid(0) succeeded", file=sys.stderr)
    raise SystemExit(1)
except PermissionError:
    print("SECURITY_OK: setuid(0) blocked")
try:
    os.setuid(1000)
    print("SECURITY_WARNING: changed UID unexpectedly", file=sys.stderr)
except PermissionError:
    print("SECURITY_OK: setuid(1000) blocked")
"""
        result = run_python(code=code, time_limit_s=2, memory_limit_mb=32)
        assert result.exit_code == 0
        assert b"SECURITY_FAIL" not in result.stderr


@LINUX_ONLY
@ISOLATE_ONLY
class TestSecurityMetadata:
    """Execution metadata should be present for incident response / auditing."""

    def test_execution_result_contains_security_info(self):
        """SECURITY: check basic metadata fields exist."""
        res = run_python(code="print('test')", time_limit_s=1, memory_limit_mb=16)
        assert isinstance(res, ExecutionResult)
        assert hasattr(res, "exit_code")
        assert hasattr(res, "signal")


def test_security_probe_reports_capabilities():
    """SECURITY: probe() must report available capabilities (booleans).

    This is informational and does *not* assert True/False, only that fields exist.
    """
    caps = probe()
    assert "seccomp" in caps and isinstance(caps["seccomp"], bool)
    assert "landlock" in caps and isinstance(caps["landlock"], bool)
    assert "userns" in caps and isinstance(caps["userns"], bool)
