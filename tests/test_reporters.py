import json
from pathlib import Path

from watchglass.models import Finding, Severity
from watchglass.reporters import render_html, render_json


def sample() -> list[Finding]:
    return [
        Finding("RS001", "Key", Severity.CRITICAL, "[REDACTED]", Path("a.env"), 2, "Rotate it.")
    ]


def test_json_report_is_structured() -> None:
    report = json.loads(render_json(sample()))
    assert report["summary"]["findings"] == 1
    assert report["findings"][0]["rule_id"] == "RS001"


def test_html_report_escapes_evidence() -> None:
    finding = sample()[0]
    unsafe = [
        Finding(
            finding.rule_id,
            finding.title,
            finding.severity,
            "<script>",
            finding.path,
            finding.line,
            finding.recommendation,
        )
    ]
    report = render_html(unsafe)
    assert "&lt;script&gt;" in report
    assert "<script>" not in report
