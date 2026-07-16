from pathlib import Path

from watchglass.models import Finding, Severity


def test_finding_serialization() -> None:
    finding = Finding(
        rule_id="RS000",
        title="Example",
        severity=Severity.HIGH,
        evidence="redacted",
        path=Path("config/app.yml"),
        line=3,
        recommendation="Fix it.",
    )

    assert finding.to_dict()["severity"] == "high"
    assert finding.to_dict()["path"] == "config/app.yml"
    assert Severity.CRITICAL.rank > Severity.HIGH.rank
