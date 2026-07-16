"""Secret and private-key heuristics."""

from __future__ import annotations

import re

from watchglass.checks.common import finding
from watchglass.core.files import ScannedFile
from watchglass.models import Finding, Severity

PATTERNS = (
    (
        "RS001",
        "Private key committed",
        Severity.CRITICAL,
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    ),
    ("RS002", "AWS access key exposed", Severity.CRITICAL, re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    (
        "RS003",
        "GitHub token exposed",
        Severity.CRITICAL,
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,255}\b"),
    ),
    (
        "RS004",
        "Hard-coded secret",
        Severity.HIGH,
        re.compile(
            r"(?i)\b(?:api[_-]?key|secret|token|password|passwd)\b\s*[:=]\s*['\"]?([^\s'\"#]{8,})"
        ),
    ),
)
PLACEHOLDERS = {"changeme", "example", "placeholder", "your_secret_here"}


def check_secrets(file: ScannedFile) -> list[Finding]:
    findings: list[Finding] = []
    for number, line in enumerate(file.text.splitlines(), 1):
        for rule_id, title, severity, pattern in PATTERNS:
            match = pattern.search(line)
            if not match:
                continue
            value = match.group(1) if match.lastindex else match.group(0)
            if value.lower() in PLACEHOLDERS:
                continue
            evidence = f"{line[: match.start()].strip()} [REDACTED]".strip()
            findings.append(
                finding(
                    file,
                    number,
                    rule_id,
                    title,
                    severity,
                    evidence,
                    (
                        "Remove the value, rotate it, and load it from a secret "
                        "manager or environment."
                    ),
                )
            )
    return findings
