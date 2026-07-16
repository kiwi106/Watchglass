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
                    "GitHub Action uses a mutable reference",
                    Severity.HIGH,
                    line,
                    "Pin third-party actions to a reviewed full commit SHA.",
                )
            )
        if re.search(r"(?:pull_request_target\s*:|\bon\s*:\s*pull_request_target\b)", line):
            findings.append(
                finding(
                    file,
                    number,
                    "RS041",
                    "pull_request_target trigger used",
                    Severity.HIGH,
                    line,
                    "Avoid running untrusted pull-request code with target-repository secrets.",
                )
            )
        if re.search(r"permissions\s*:\s*write-all\b", line, re.IGNORECASE):
            findings.append(
                finding(
                    file,
                    number,
                    "RS042",
                    "Workflow grants write-all",
                    Severity.HIGH,
                    line,
                    "Grant the minimum permissions per workflow or job.",
                )
            )
    return findings
