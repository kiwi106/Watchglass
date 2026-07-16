"""JSON reporter."""

from __future__ import annotations

import json

from watchglass.models import Finding, Severity


def render_json(findings: list[Finding]) -> str:
    by_severity = {
        severity.value: sum(item.severity is severity for item in findings) for severity in Severity
    }
    return json.dumps(
        {
            "summary": {"findings": len(findings), "by_severity": by_severity},
            "findings": [item.to_dict() for item in findings],
        },
        indent=2,
        ensure_ascii=False,
    )
