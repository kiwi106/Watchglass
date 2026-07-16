"""Helpers shared by checks."""

from __future__ import annotations

import re

from watchglass.core.files import ScannedFile
from watchglass.models import Finding, Severity


def finding(
    file: ScannedFile,
    line: int,
    rule_id: str,
    title: str,
    severity: Severity,
    evidence: str,
    recommendation: str,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        severity=severity,
        evidence=evidence.strip()[:160],
        path=file.relative_path,
        line=line,
        recommendation=recommendation,
    )


def matching_lines(file: ScannedFile, pattern: str) -> list[tuple[int, str, re.Match[str]]]:
    regex = re.compile(pattern, re.IGNORECASE)
    return [
        (number, line, match)
        for number, line in enumerate(file.text.splitlines(), 1)
        if (match := regex.search(line))
    ]
