"""Rich terminal reporter."""

from __future__ import annotations

from rich.console import Console
from rich.table import Table

from watchglass.models import Finding


def render_terminal(findings: list[Finding], console: Console) -> None:
    table = Table(title=f"Watchglass — {len(findings)} finding(s)")
    table.add_column("Severity")
    table.add_column("Rule")
    table.add_column("Location")
    table.add_column("Finding")
    table.add_column("Recommendation")
    colors = {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "blue",
        "info": "cyan",
    }
    for item in findings:
        severity = item.severity.value
        table.add_row(
            f"[{colors[severity]}]{severity.upper()}[/]",
            item.rule_id,
            f"{item.path}:{item.line or '-'}",
            f"{item.title}\n[dim]{item.evidence}[/]",
            item.recommendation,
        )
    console.print(table)
    if not findings:
        console.print("[green]No finding detected by the enabled checks.[/green]")
