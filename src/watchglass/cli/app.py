"""Typer application."""

from __future__ import annotations

from enum import StrEnum
from io import StringIO
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from watchglass import __version__
from watchglass.core import scan as run_scan
from watchglass.models import Severity
from watchglass.reporters import render_html, render_json, render_terminal

app = typer.Typer(
    help="Audit Git repositories locally for security misconfigurations.", no_args_is_help=True
)
console = Console()


class OutputFormat(StrEnum):
    TERMINAL = "terminal"
    JSON = "json"
    HTML = "html"


def version_callback(value: bool) -> None:
    if value:
        typer.echo(f"Watchglass {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option("--version", callback=version_callback, is_eager=True, help="Show version."),
    ] = False,
) -> None:
    """Watchglass performs read-only, offline static analysis."""


@app.command()
def scan(
    path: Annotated[Path, typer.Argument(help="Repository directory to scan.")] = Path("."),
    format_: Annotated[
        OutputFormat, typer.Option("--format", "-f", help="Output format.")
    ] = OutputFormat.TERMINAL,
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Write report to this file.")
    ] = None,
    fail_on: Annotated[
        Severity, typer.Option(help="Exit 1 at or above this severity.")
    ] = Severity.HIGH,
) -> None:
    """Scan PATH without network access or code execution."""
    try:
        findings = run_scan(path)
    except ValueError as error:
        raise typer.BadParameter(str(error), param_hint="PATH") from error

    if format_ is OutputFormat.TERMINAL:
        if output is not None:
            file_console = Console(file=StringIO(), record=True, force_terminal=False)
            render_terminal(findings, file_console)
            output.write_text(file_console.export_text(), encoding="utf-8")
        else:
            render_terminal(findings, console)
    else:
        report = render_json(findings) if format_ is OutputFormat.JSON else render_html(findings)
        if output is None:
            typer.echo(report)
        else:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(report, encoding="utf-8")
            console.print(f"Report written to [bold]{output}[/bold]")

    if any(item.severity.rank >= fail_on.rank for item in findings):
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
