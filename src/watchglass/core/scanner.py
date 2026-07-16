"""Rule orchestration."""

from __future__ import annotations

from pathlib import Path

from watchglass.checks import ALL_CHECKS
from watchglass.core.files import discover_files
from watchglass.models import Finding


def scan(root: str | Path) -> list[Finding]:
    """Scan a local directory and return stable, sorted findings."""
    root = Path(root).expanduser().resolve()
    if not root.is_dir():
        raise ValueError(f"Not a directory: {root}")
    findings = [
        finding for file in discover_files(root) for check in ALL_CHECKS for finding in check(file)
    ]
    return sorted(
        findings,
        key=lambda item: (
            -item.severity.rank,
            item.path.as_posix(),
            item.line or 0,
            item.rule_id,
        ),
    )
