from pathlib import Path

from watchglass.core import scan

FIXTURES = Path(__file__).parent / "fixtures"


def test_vulnerable_project_covers_initial_rule_families() -> None:
    findings = scan(FIXTURES / "vulnerable_project")
    rule_ids = {finding.rule_id for finding in findings}

    assert {"RS004", "RS010", "RS020", "RS021", "RS023", "RS024"} <= rule_ids
    assert {"RS030", "RS032", "RS033"} <= rule_ids
    assert {"RS040", "RS041", "RS042"} <= rule_ids
    assert all(finding.evidence and finding.recommendation for finding in findings)
    assert all(finding.line is not None for finding in findings)
    assert "supersecretvalue123" not in repr([finding.to_dict() for finding in findings])


def test_secure_project_has_no_findings() -> None:
    assert scan(FIXTURES / "secure_project") == []


def test_scan_rejects_file() -> None:
    try:
        scan(__file__)
    except ValueError as error:
        assert "n'est pas un répertoire" in str(error)
    else:
        raise AssertionError("Expected ValueError")


def test_scan_accepts_string_path_and_detects_pull_request_target() -> None:
    findings = scan(str(FIXTURES / "vulnerable_project"))

    assert any(finding.rule_id == "RS041" for finding in findings)
