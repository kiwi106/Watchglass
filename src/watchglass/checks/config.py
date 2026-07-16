"""Framework-agnostic configuration heuristics."""

from __future__ import annotations

from watchglass.checks.common import finding, matching_lines
from watchglass.core.files import ScannedFile
from watchglass.models import Finding, Severity


def check_config(file: ScannedFile) -> list[Finding]:
    findings: list[Finding] = []
    rules = (
        (
            r"\bdebug\b\s*[:=]\s*(?:true|1|yes|on)\b",
            "RS020",
            "Debug mode enabled",
            Severity.HIGH,
            "Disable debug mode outside local development.",
        ),
        (
            r"(?:allow[_-]?origins|cors[_-]?origins?)\s*[:=]\s*(?:\[?['\"]?\*|['\"]\*)",
            "RS021",
            "Permissive CORS origin",
            Severity.HIGH,
            "Allow only explicit trusted origins.",
        ),
        (
            r"(?:allow[_-]?credentials)\s*[:=]\s*(?:true|1|yes|on)\b",
            "RS022",
            "CORS credentials enabled",
            Severity.MEDIUM,
            "Enable credentials only with a strict origin allowlist.",
        ),
        (
            r"(?:secure|cookie[_-]?secure)\s*[:=]\s*(?:false|0|no|off)\b",
            "RS023",
            "Cookie Secure flag disabled",
            Severity.HIGH,
            "Set Secure for cookies used over HTTPS.",
        ),
        (
            r"(?:httponly|http_only|cookie[_-]?httponly)\s*[:=]\s*(?:false|0|no|off)\b",
            "RS024",
            "Cookie HttpOnly flag disabled",
            Severity.MEDIUM,
            "Set HttpOnly on session and authentication cookies.",
        ),
        (
            r"(?:samesite|same_site)\s*[:=]\s*['\"]?none\b",
            "RS025",
            "Cookie SameSite=None",
            Severity.MEDIUM,
            "Prefer SameSite=Lax or Strict; pair None with Secure when required.",
        ),
    )
    for pattern, rule_id, title, severity, recommendation in rules:
        for number, line, _ in matching_lines(file, pattern):
            findings.append(finding(file, number, rule_id, title, severity, line, recommendation))
    return findings
