import json
import sys
from pathlib import Path
from typing import List, Optional

import typer

from .api import probe, run_python
from .exceptions import PyenclaveError

app = typer.Typer(
    name="pyenclave",
    help="Run untrusted Python code safely with native Linux isolation",
    add_completion=False,
)


@app.command("run")
def cli_run(
    code: Optional[str] = typer.Option(
        None, "--code", "-c",
        help="Python code to execute"
    ),
    script: Optional[Path] = typer.Option(
        None, "--script", "-s",
        help="Python script file to execute"
    ),
    module: Optional[str] = typer.Option(
        None, "--module", "-m",
        help="Python module to execute"
    ),
    args: Optional[List[str]] = typer.Argument(
        None,
        help="Arguments to pass to script/module"
    ),
    time_limit: Optional[int] = typer.Option(
        None, "--time-limit", "-t",
        help="Time limit in seconds"
    ),
    memory_limit: Optional[int] = typer.Option(
        None, "--memory-limit",
        help="Memory limit in MB"
    ),
    network: bool = typer.Option(
        False, "--network",
        help="Allow network access (default: blocked)"
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v",
        help="Show execution metadata"
    ),
):
    """Execute Python code in an isolated sandbox.

    Examples:

        Run inline code:
        $ pyenclave run -c "print('Hello from sandbox')"

        Run a script with arguments:
        $ pyenclave run -s script.py arg1 arg2

        Run a module:
        $ pyenclave run -m json.tool < data.json

        With resource limits:
        $ pyenclave run -c "import time; time.sleep(10)" --time-limit 2 --memory-limit 128
    """
    try:
        script_str = str(script) if script else None

        result = run_python(
            code=code,
            script=script_str,
            module=module,
            args=args or [],
            time_limit_s=time_limit,
            memory_limit_mb=memory_limit,
            network=network,
        )

        if result.stdout:
            sys.stdout.buffer.write(result.stdout)
            sys.stdout.buffer.flush()

        if result.stderr:
            sys.stderr.buffer.write(result.stderr)
            sys.stderr.buffer.flush()

        if verbose:
            _print_execution_metadata(result)

        sys.exit(result.exit_code or 0)

    except PyenclaveError as e:
        typer.echo(f"Error: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        typer.echo(f"Unexpected error: {e}", err=True)
        sys.exit(1)


@app.command("probe")
def cli_probe(
    json_output: bool = typer.Option(
        False, "--json",
        help="Output in JSON format"
    ),
):
    """Check host system security capabilities.

    Probes for:
        - User namespaces support
        - Seccomp-BPF availability
        - Landlock LSM support and ABI version
        - System architecture and kernel version

    Examples:

        Human-readable output:
        $ pyenclave probe

        Machine-readable JSON:
        $ pyenclave probe --json
    """
    try:
        capabilities = probe()

        if json_output:
            typer.echo(json.dumps(capabilities, indent=2))
        else:
            _print_capabilities_report(capabilities)

    except Exception as e:
        typer.echo(f"Error: {e}", err=True)
        sys.exit(1)


def main():
    """Entry point for CLI."""
    app()


def _print_execution_metadata(result):
    """Print execution metadata in verbose mode."""
    typer.echo(f"\n[Exit code: {result.exit_code}]", err=True)

    if result.signal:
        typer.echo(f"[Signal: {result.signal}]", err=True)

    if result.cpu_time_ms:
        typer.echo(f"[CPU time: {result.cpu_time_ms}ms]", err=True)

    if result.peak_rss_kb:
        typer.echo(f"[Peak RSS: {result.peak_rss_kb}KB]", err=True)

    if result.reason:
        typer.echo(f"[Reason: {result.reason}]", err=True)


def _print_capabilities_report(capabilities: dict):
    """Print human-readable capabilities report."""
    typer.echo("🔍 Host Security Capabilities:")
    typer.echo()

    userns = capabilities.get("userns")
    seccomp = capabilities.get("seccomp")
    landlock = capabilities.get("landlock")
    landlock_abi = capabilities.get("landlock_abi")

    typer.echo(f"  User namespaces:  {'✓' if userns else '✗'}")
    typer.echo(f"  Seccomp-BPF:      {'✓' if seccomp else '✗'}")

    if landlock and landlock_abi:
        typer.echo(f"  Landlock LSM:     ✓ (ABI v{landlock_abi})")
    else:
        typer.echo("  Landlock LSM:     ✗")

    typer.echo()
    typer.echo(f"  Architecture:     {capabilities.get('arch', 'unknown')}")
    typer.echo(f"  Kernel version:   {capabilities.get('kernel', 'unknown')}")

    all_available = all([userns, seccomp, landlock])

    typer.echo()
    if all_available:
        typer.echo("✅ All security features available!")
        typer.echo("   Full sandboxing capabilities enabled.")
    else:
        typer.echo("⚠️  Some security features are missing:")
        if not userns:
            typer.echo("   - User namespaces: Required for process isolation")
        if not seccomp:
            typer.echo("   - Seccomp-BPF: Required for syscall filtering")
        if not landlock:
            typer.echo("   - Landlock LSM: Required for filesystem access control")
        typer.echo()
        typer.echo("   Sandboxing may be incomplete or unavailable.")


if __name__ == "__main__":
    main()
