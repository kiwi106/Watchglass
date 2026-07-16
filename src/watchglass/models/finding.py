"""Normalized result emitted by every security check."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any


class Severity(StrEnum):
    """Finding severity, ordered from informational to critical."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return list(type(self)).index(self)


@dataclass(frozen=True, slots=True)
class Finding:
    """A single actionable and traceable security observation."""

    rule_id: str
    title: str
    severity: Severity
    evidence: str
    path: Path
    line: int | None
    recommendation: str
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        result = asdict(self)
        result["severity"] = self.severity.value
        result["path"] = self.path.as_posix()
        return result
