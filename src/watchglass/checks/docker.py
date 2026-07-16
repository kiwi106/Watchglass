"""Basic Dockerfile checks."""

from __future__ import annotations

import re

from watchglass.checks.common import finding
from watchglass.core.files import ScannedFile
from watchglass.models import Finding, Severity


def check_dockerfile(file: ScannedFile) -> list[Finding]:
    if not file.relative_path.name.lower().startswith("dockerfile"):
        return []
    findings: list[Finding] = []
    lines = file.text.splitlines()
    for number, line in enumerate(lines, 1):
        stripped = line.strip()
        if re.match(r"FROM\s+\S+:latest(?:\s|$)", stripped, re.IGNORECASE):
            findings.append(
                finding(
                    file,
                    number,
                    "RS030",
                    "Unpinned Docker base image",
                    Severity.MEDIUM,
                    stripped,
                    "Pin the image to an immutable digest or reviewed version.",
                )
            )
        if re.match(r"ADD\s+https?://", stripped, re.IGNORECASE):
            findings.append(
                finding(
                    file,
                    number,
                    "RS031",
                    "Remote URL used with ADD",
                    Severity.MEDIUM,
                    stripped,
                    "Download with verification in a controlled build step.",
                )
            )
        if re.search(r"\b(?:curl|wget)\b.*\|\s*(?:sh|bash)\b", stripped, re.IGNORECASE):
            findings.append(
                finding(
                    file,
                    number,
                    "RS032",
                    "Downloaded script piped to shell",
                    Severity.HIGH,
                    stripped,
                    "Download, pin, verify, then execute the artifact explicitly.",
                )
            )
    has_user = any(re.match(r"\s*USER\s+\S+", line, re.IGNORECASE) for line in lines)
    if not has_user:
        findings.append(
            finding(
                file,
                1,
                "RS033",
                "Container may run as root",
                Severity.MEDIUM,
                "No USER instruction",
                "Create and select a non-root user in the final stage.",
            )
        )
    return findings
