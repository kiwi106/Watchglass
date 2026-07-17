"""Secret and private-key heuristics."""

from __future__ import annotations

import re

from watchglass.checks.common import finding
from watchglass.core.files import ScannedFile
from watchglass.models import Finding, Severity

PATTERNS = (
    (
        "RS001",
        "Clé privée présente dans le dépôt",
        Severity.CRITICAL,
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    ),
    ("RS002", "Clé d'accès AWS exposée", Severity.CRITICAL, re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    (
        "RS003",
        "Jeton GitHub exposé",
        Severity.CRITICAL,
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,255}\b"),
    ),
    (
        "RS004",
        "Secret codé en dur",
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
                        "Supprimez la valeur, renouvelez-la et chargez-la depuis un gestionnaire "
                        "de secrets ou l'environnement."
                    ),
                )
            )
    return findings
