from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from triflow.cli import app

runner = CliRunner()

TOXIC_CONFIG: dict[str, object] = {
    "mcpServers": {
        "files": {"command": "npx", "args": ["@modelcontextprotocol/server-filesystem", "/d"]},
        "fetch": {"command": "uvx", "args": ["mcp-server-fetch"]},
        "gmail": {"command": "npx", "args": ["gmail-mcp"]},
    }
}
BENIGN_CONFIG: dict[str, object] = {"mcpServers": {"calc": {"command": "acme-calc"}}}
SKILLS = Path(__file__).parent / "fixtures" / "skills"


def write_config(tmp_path: Path, data: dict[str, object]) -> Path:
    path = tmp_path / "mcp.json"
    path.write_text(json.dumps(data))
    return path


class TestScan:
    def test_config_only_scan_reports_trifecta_and_exits_1(self, tmp_path: Path) -> None:
        config = write_config(tmp_path, TOXIC_CONFIG)
        result = runner.invoke(app, ["scan", "-c", str(config), "--no-introspect"])
        assert result.exit_code == 1  # fail-on defaults to high; trifecta is critical
        assert "TRIFLOW-TRIFECTA" in result.output

    def test_benign_scan_exits_0(self, tmp_path: Path) -> None:
        config = write_config(tmp_path, BENIGN_CONFIG)
        result = runner.invoke(app, ["scan", "-c", str(config), "--no-introspect"])
        assert result.exit_code == 0
        assert "No findings" in result.output

    def test_json_format(self, tmp_path: Path) -> None:
        config = write_config(tmp_path, TOXIC_CONFIG)
        result = runner.invoke(
            app, ["scan", "-c", str(config), "--no-introspect", "-f", "json", "--fail-on", "low"]
        )
        payload = json.loads(result.output)
        assert payload["summary"]["by_severity"]["critical"] >= 1

    def test_sarif_written_to_file(self, tmp_path: Path) -> None:
        config = write_config(tmp_path, TOXIC_CONFIG)
        out = tmp_path / "out.sarif"
        runner.invoke(
            app,
            ["scan", "-c", str(config), "--no-introspect", "-f", "sarif", "-o", str(out)],
        )
        assert out.exists()
        sarif = json.loads(out.read_text())
        assert sarif["version"] == "2.1.0"

    def test_no_fail_reports_but_exits_0(self, tmp_path: Path) -> None:
        config = write_config(tmp_path, TOXIC_CONFIG)
        result = runner.invoke(app, ["scan", "-c", str(config), "--no-introspect", "--no-fail"])
        assert result.exit_code == 0  # gate disabled...
        assert "TRIFLOW-TRIFECTA" in result.output  # ...but the finding is still reported

    def test_fail_on_medium_still_gates_on_critical(self, tmp_path: Path) -> None:
        config = write_config(tmp_path, TOXIC_CONFIG)
        result = runner.invoke(
            app, ["scan", "-c", str(config), "--no-introspect", "--fail-on", "critical"]
        )
        assert result.exit_code == 1  # trifecta IS critical

    def test_empty_discovery_is_clean(self, tmp_path: Path) -> None:
        result = runner.invoke(
            app, ["scan", "--home", str(tmp_path), "--project", str(tmp_path), "--no-introspect"]
        )
        assert result.exit_code == 0
        assert "No MCP servers discovered" in result.output


class TestLintSkills:
    def test_flags_overbroad_skill(self) -> None:
        result = runner.invoke(app, ["lint-skills", str(SKILLS / "overbroad" / "SKILL.md")])
        assert result.exit_code == 1
        assert "UNBOUNDED" in result.output.upper()

    def test_safe_skill_exits_0(self) -> None:
        result = runner.invoke(app, ["lint-skills", str(SKILLS / "safe" / "SKILL.md")])
        assert result.exit_code == 0

    def test_json_output(self) -> None:
        result = runner.invoke(app, ["lint-skills", str(SKILLS), "-f", "json", "--fail-on", "low"])
        payload = json.loads(result.output)
        assert payload["summary"]["total"] >= 1


class TestMeta:
    def test_version(self) -> None:
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0

    def test_rules_lists_all(self) -> None:
        result = runner.invoke(app, ["rules"])
        assert "TRIFLOW-TRIFECTA" in result.output
        assert "TRIFLOW-SKILL-UNBOUNDED-SHELL" in result.output
