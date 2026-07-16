import json

from typer.testing import CliRunner

from watchglass.cli.app import app

runner = CliRunner()


def test_cli_json_output_for_secure_project() -> None:
    result = runner.invoke(app, ["scan", "tests/fixtures/secure_project", "--format", "json"])
    assert result.exit_code == 0
    assert json.loads(result.stdout)["summary"]["findings"] == 0


def test_cli_fails_on_high_findings() -> None:
    result = runner.invoke(app, ["scan", "tests/fixtures/vulnerable_project", "--format", "json"])
    assert result.exit_code == 1


def test_cli_writes_html(tmp_path) -> None:
    output = tmp_path / "report.html"
    result = runner.invoke(
        app,
        ["scan", "tests/fixtures/secure_project", "--format", "html", "--output", str(output)],
    )
    assert result.exit_code == 0
    assert "Watchglass security report" in output.read_text(encoding="utf-8")
