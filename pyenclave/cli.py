"""
CLI opcional. Pode ser ativada via `python -m pyenclave ...`.
"""

import typer

app = typer.Typer(help="pyenclave CLI (skeleton)")


@app.command("run")
def cli_run():
    """
    TODO: mapear flags → api.run_python(...)
    """
    # TODO
    typer.echo("pyenclave run (skeleton)")


def main():
    app()


if __name__ == "__main__":
    main()
