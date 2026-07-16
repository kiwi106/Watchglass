"""Sensitive file checks."""

from __future__ import annotations

from watchglass.checks.common import finding
from watchglass.core.files import ScannedFile
from watchglass.models import Finding, Severity

SENSITIVE_NAMES = {
    ".env",
    ".env.local",
    ".env.production",
    ".env.development",
    "credentials.json",
    "secrets.yml",
    "secrets.yaml",
    "id_rsa",
    "id_ed25519",
}
PRIVATE_SUFFIXES = {".key", ".p12", ".pfx", ".pem", ".crt", ".cer"}


def check_sensitive_files(file: ScannedFile) -> list[Finding]:
    name = file.relative_path.name.lower()
    if (
        name not in SENSITIVE_NAMES
        and not (name.startswith(".env.") and name not in {".env.example", ".env.template"})
        and file.relative_path.suffix.lower() not in PRIVATE_SUFFIXES
    ):
        return []
    return [
        finding(
            file,
            1,
            "RS010",
            "Sensitive file present",
            Severity.HIGH,
            f"Sensitive filename: {file.relative_path.name}",
            "Remove it from version control, add an ignore rule, and provide a redacted template.",
        )
    ]
