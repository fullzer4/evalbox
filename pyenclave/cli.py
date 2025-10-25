"""
CLI para pyenclave. Pode ser ativada via `python -m pyenclave ...`.
"""

import sys
import typer
from typing import Optional, List
from pathlib import Path
import json

from .api import run_python, probe

app = typer.Typer(
    name="pyenclave",
    help="Hermetic Python sandbox for untrusted code execution",
    add_completion=False,
)


@app.command("run")
def cli_run(
    code: Optional[str] = typer.Option(None, "--code", "-c", help="Python code to execute"),
    script: Optional[Path] = typer.Option(None, "--script", "-s", help="Python script file to execute"),
    module: Optional[str] = typer.Option(None, "--module", "-m", help="Python module to execute"),
    args: Optional[List[str]] = typer.Argument(None, help="Arguments to pass to script/module"),
    time_limit: Optional[int] = typer.Option(None, "--time-limit", "-t", help="Time limit in seconds"),
    memory_limit: Optional[int] = typer.Option(None, "--memory-limit", help="Memory limit in MB"),
    network: bool = typer.Option(False, "--network", help="Allow network access (default: blocked)"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
):
    """
    Execute Python code in an isolated sandbox.
    
    Examples:
    
      # Run inline code
      pyenclave run -c "print('Hello from sandbox')"
      
      # Run a script
      pyenclave run -s script.py arg1 arg2
      
      # Run a module
      pyenclave run -m json.tool < data.json
      
      # With time limit
      pyenclave run -c "import time; time.sleep(10)" --time-limit 2
    """
    try:
        # Convert script Path to string if provided
        script_str = str(script) if script else None
        
        # Execute
        result = run_python(
            code=code,
            script=script_str,
            module=module,
            args=args or [],
            time_limit_s=time_limit,
            memory_limit_mb=memory_limit,
            network=network,
        )
        
        # Output stdout
        if result.stdout:
            sys.stdout.buffer.write(result.stdout)
            sys.stdout.buffer.flush()
        
        # Output stderr
        if result.stderr:
            sys.stderr.buffer.write(result.stderr)
            sys.stderr.buffer.flush()
        
        # Verbose info
        if verbose:
            typer.echo(f"\n[Exit code: {result.exit_code}]", err=True)
            if result.signal:
                typer.echo(f"[Signal: {result.signal}]", err=True)
            if result.cpu_time_ms:
                typer.echo(f"[CPU time: {result.cpu_time_ms}ms]", err=True)
            if result.peak_rss_kb:
                typer.echo(f"[Peak RSS: {result.peak_rss_kb}KB]", err=True)
        
        # Exit with same code
        sys.exit(result.exit_code or 0)
        
    except ValueError as e:
        typer.echo(f"Error: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        typer.echo(f"Unexpected error: {e}", err=True)
        sys.exit(1)


@app.command("probe")
def cli_probe(
    json_output: bool = typer.Option(False, "--json", help="Output in JSON format"),
):
    """
    Check host capabilities (namespaces, seccomp, Landlock, etc).
    
    Example:
      pyenclave probe
      pyenclave probe --json
    """
    try:
        capabilities = probe()
        
        if json_output:
            typer.echo(json.dumps(capabilities, indent=2))
        else:
            typer.echo("🔍 Host Capabilities:")
            typer.echo(f"  User namespaces:  {'✓' if capabilities.get('userns') else '✗'}")
            typer.echo(f"  Seccomp:          {'✓' if capabilities.get('seccomp') else '✗'}")
            
            landlock = capabilities.get('landlock')
            landlock_abi = capabilities.get('landlock_abi')
            if landlock and landlock_abi:
                typer.echo(f"  Landlock:         ✓ (ABI v{landlock_abi})")
            else:
                typer.echo("  Landlock:         ✗")
            
            typer.echo(f"  Architecture:     {capabilities.get('arch', 'unknown')}")
            typer.echo(f"  Kernel:           {capabilities.get('kernel', 'unknown')}")
            
            # Overall assessment
            all_good = all([
                capabilities.get('userns'),
                capabilities.get('seccomp'),
                capabilities.get('landlock'),
            ])
            
            typer.echo()
            if all_good:
                typer.echo("✅ All security features available!")
            else:
                typer.echo("⚠️  Some security features are missing.")
                typer.echo("   Sandboxing may be incomplete.")
    
    except Exception as e:
        typer.echo(f"Error: {e}", err=True)
        sys.exit(1)


def main():
    app()


if __name__ == "__main__":
    main()
