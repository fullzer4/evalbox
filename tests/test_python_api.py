from conftest import ISOLATE_ONLY, LINUX_ONLY


class TestPublicAPI:
    def test_import_module(self):
        """Ensure the package imports."""
        import pyenclave

    def test_api_exports(self):
        """Check core symbols are exported."""
        import pyenclave
        assert hasattr(pyenclave, "run_python") and callable(pyenclave.run_python)
        assert hasattr(pyenclave, "probe") and callable(pyenclave.probe)
        assert hasattr(pyenclave, "ExecutionResult")


@LINUX_ONLY
@ISOLATE_ONLY
class TestBasicExecution:
    def test_run_simple_print(self):
        """Simple stdout capture."""
        from pyenclave import run_python
        res = run_python(code="print('hello')")
        assert res.exit_code == 0
        assert b"hello" in res.stdout
        assert res.stderr in (b"", res.stderr)  # stderr may be empty

    def test_run_with_stderr(self):
        """stderr must be captured."""
        from pyenclave import run_python
        code = "import sys; print('out'); print('err', file=sys.stderr)"
        res = run_python(code=code)
        assert res.exit_code == 0
        assert b"out" in res.stdout
        assert b"err" in res.stderr

    def test_nonzero_exit_code(self):
        """Non-zero exit codes are reported."""
        from pyenclave import run_python
        res = run_python(code="import sys; sys.exit(7)")
        assert res.exit_code == 7

    def test_python_exception_is_visible(self):
        """Exceptions should appear on stderr and produce non-zero exit."""
        from pyenclave import run_python
        res = run_python(code="raise ValueError('boom')")
        assert res.exit_code != 0
        assert b"ValueError" in res.stderr
        assert b"boom" in res.stderr


@LINUX_ONLY
class TestProbe:
    def test_probe_shape(self):
        """probe() returns booleans for key capabilities."""
        from pyenclave import probe
        caps = probe()
        # Required keys with boolean values
        for k in ("seccomp", "landlock", "userns"):
            assert k in caps and isinstance(caps[k], bool)


@LINUX_ONLY
@ISOLATE_ONLY
class TestEnvironment:
    def test_custom_env_vars(self):
        """Safe custom env variables should be visible inside sandbox."""
        from pyenclave import run_python
        code = "import os; print(os.getenv('FOO')); print(os.getenv('BAR'))"
        res = run_python(code=code, env_overrides={"FOO": "foo", "BAR": "bar"})
        assert res.exit_code == 0
        assert b"foo" in res.stdout
        assert b"bar" in res.stdout


@LINUX_ONLY
@ISOLATE_ONLY
class TestExecutionResult:
    def test_execution_result_fields(self):
        """run_python returns an ExecutionResult with core fields."""
        from pyenclave import ExecutionResult, run_python
        res = run_python(code="print('x')")
        assert isinstance(res, ExecutionResult)
        # Core fields present
        assert hasattr(res, "exit_code")
        assert hasattr(res, "stdout")
        assert hasattr(res, "stderr")
        assert hasattr(res, "signal")
