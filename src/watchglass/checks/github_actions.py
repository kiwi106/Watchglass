"""GitHub Actions workflow checks."""

from __future__ import annotations

import re

from watchglass.checks.common import finding
from watchglass.core.files import ScannedFile
from watchglass.models import Finding, Severity


def check_github_actions(file: ScannedFile) -> list[Finding]:
    parts = file.relative_path.parts
    if (
        len(parts) < 3
        or parts[:2] != (".github", "workflows")
        or file.relative_path.suffix not in {".yml", ".yaml"}
    ):
        return []
    findings: list[Finding] = []
    for number, line in enumerate(file.text.splitlines(), 1):
        if re.search(r"uses:\s*[^\s]+@(master|main|latest)\b", line, re.IGNORECASE):
            findings.append(
                finding(
                    file,
                    number,
                    "RS040",
                    "Action GitHub utilisant une référence mutable",
                    Severity.HIGH,
                    line,
                    "Épinglez les actions tierces à un SHA de commit complet et vérifié.",
                )
            )
        if re.search(r"(?:pull_request_target\s*:|\bon\s*:\s*pull_request_target\b)", line):
            findings.append(
                finding(
                    file,
                    number,
                    "RS041",
                    "Déclencheur pull_request_target utilisé",
                    Severity.HIGH,
                    line,
                    "Évitez d'exécuter du code non fiable avec les secrets du dépôt cible.",
                )
            )
        if re.search(r"permissions\s*:\s*write-all\b", line, re.IGNORECASE):
            findings.append(
                finding(
                    file,
                    number,
                    "RS042",
                    "Workflow accordant write-all",
                    Severity.HIGH,
                    line,
                    "Accordez le minimum de permissions pour chaque workflow ou tâche.",
                )
            )
    return findings
