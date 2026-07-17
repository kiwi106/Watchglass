"""Rich terminal reporter."""

from __future__ import annotations

from rich.console import Console
from rich.table import Table

from watchglass.models import Finding


def render_terminal(findings: list[Finding], console: Console) -> None:
    table = Table(title=f"Watchglass — {len(findings)} constat(s)")
    table.add_column("Gravité")
    table.add_column("Règle")
    table.add_column("Emplacement")
    table.add_column("Constat")
    table.add_column("Recommandation")
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
        console.print("[green]Aucun constat détecté par les vérifications activées.[/green]")
