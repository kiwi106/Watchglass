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
            "Mode débogage activé",
            Severity.HIGH,
            "Désactivez le mode débogage hors de l'environnement de développement local.",
        ),
        (
            r"(?:allow[_-]?origins|cors[_-]?origins?)\s*[:=]\s*(?:\[?['\"]?\*|['\"]\*)",
            "RS021",
            "Origine CORS trop permissive",
            Severity.HIGH,
            "N'autorisez que des origines de confiance explicitement définies.",
        ),
        (
            r"(?:allow[_-]?credentials)\s*[:=]\s*(?:true|1|yes|on)\b",
            "RS022",
            "Identifiants CORS activés",
            Severity.MEDIUM,
            "N'activez les identifiants qu'avec une liste stricte d'origines autorisées.",
        ),
        (
            r"(?:secure|cookie[_-]?secure)\s*[:=]\s*(?:false|0|no|off)\b",
            "RS023",
            "Attribut Secure du cookie désactivé",
            Severity.HIGH,
            "Activez Secure pour les cookies utilisés via HTTPS.",
        ),
        (
            r"(?:httponly|http_only|cookie[_-]?httponly)\s*[:=]\s*(?:false|0|no|off)\b",
            "RS024",
            "Attribut HttpOnly du cookie désactivé",
            Severity.MEDIUM,
            "Activez HttpOnly sur les cookies de session et d'authentification.",
        ),
        (
            r"(?:samesite|same_site)\s*[:=]\s*['\"]?none\b",
            "RS025",
            "Cookie avec SameSite=None",
            Severity.MEDIUM,
            "Préférez SameSite=Lax ou Strict ; associez None à Secure lorsque nécessaire.",
        ),
    )
    for pattern, rule_id, title, severity, recommendation in rules:
        for number, line, _ in matching_lines(file, pattern):
            findings.append(finding(file, number, rule_id, title, severity, line, recommendation))
    return findings
