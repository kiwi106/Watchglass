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
                    "Image de base Docker non figée",
                    Severity.MEDIUM,
                    stripped,
                    "Épinglez l'image à un condensat immuable ou à une version vérifiée.",
                )
            )
        if re.match(r"ADD\s+https?://", stripped, re.IGNORECASE):
            findings.append(
                finding(
                    file,
                    number,
                    "RS031",
                    "URL distante utilisée avec ADD",
                    Severity.MEDIUM,
                    stripped,
                    "Téléchargez avec vérification dans une étape de construction contrôlée.",
                )
            )
        if re.search(r"\b(?:curl|wget)\b.*\|\s*(?:sh|bash)\b", stripped, re.IGNORECASE):
            findings.append(
                finding(
                    file,
                    number,
                    "RS032",
                    "Script téléchargé redirigé vers un interpréteur de commandes",
                    Severity.HIGH,
                    stripped,
                    "Téléchargez, épinglez, vérifiez, puis exécutez explicitement l'artefact.",
                )
            )
    has_user = any(re.match(r"\s*USER\s+\S+", line, re.IGNORECASE) for line in lines)
    if not has_user:
        findings.append(
            finding(
                file,
                1,
                "RS033",
                "Le conteneur peut s'exécuter en tant que root",
                Severity.MEDIUM,
                "Aucune instruction USER",
                "Créez et sélectionnez un utilisateur non root dans l'étape finale.",
            )
        )
    return findings
