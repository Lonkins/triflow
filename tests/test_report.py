from __future__ import annotations

import json
from pathlib import Path

from rich.console import Console

from tests.fleet_fixtures import benign_fleet, toxic_fleet
from triflow.catalog import FINDING_RULES, RULES_BY_ID
from triflow.engine import analyze
from triflow.models import FileLocation, Finding, FindingType, Severity
from triflow.report import render_console, to_json, to_sarif
from triflow.report.sarif import _LEVEL
from triflow.skill import lint_skills

SKILLS = Path(__file__).parent / "fixtures" / "skills"


def toxic_findings() -> tuple[Finding, ...]:
    return analyze(toxic_fleet())


class TestJson:
    def test_shape_and_summary(self) -> None:
        findings = toxic_findings()
        servers = toxic_fleet()
        payload = json.loads(to_json(findings, ("a warning",), servers=servers))
        assert payload["triflow_version"]
        assert payload["summary"]["total"] == len(findings)
        assert payload["summary"]["by_severity"]["critical"] >= 1
        assert payload["warnings"] == ["a warning"]
        assert len(payload["servers"]) == 3
        assert {s["slug"] for s in payload["servers"]} == {"test:files", "test:web", "test:mailer"}
        # every finding round-trips its rule id
        assert all(f["rule_id"] for f in payload["findings"])

    def test_benign_is_empty(self) -> None:
        payload = json.loads(to_json(analyze(benign_fleet()), servers=benign_fleet()))
        assert payload["summary"]["total"] == 0
        assert payload["findings"] == []


class TestSarif:
    def test_valid_structure(self) -> None:
        findings = toxic_findings()
        slug_to_path = {s.slug: str(s.config.config_path) for s in toxic_fleet()}
        sarif = json.loads(to_sarif(findings, slug_to_path=slug_to_path))
        assert sarif["version"] == "2.1.0"
        run = sarif["runs"][0]
        assert run["tool"]["driver"]["name"] == "triflow"
        # every result references a rule that is declared in the driver
        declared = {r["id"] for r in run["tool"]["driver"]["rules"]}
        for result in run["results"]:
            assert result["ruleId"] in declared
            assert result["level"] in {"error", "warning", "note"}
            assert result["locations"]

    def test_security_severity_present(self) -> None:
        sarif = json.loads(to_sarif(toxic_findings()))
        for rule in sarif["runs"][0]["tool"]["driver"]["rules"]:
            assert "security-severity" in rule["properties"]

    def test_fleet_finding_anchors_to_config_file(self) -> None:
        findings = toxic_findings()
        slug_to_path = {s.slug: "/path/to/config.json" for s in toxic_fleet()}
        sarif = json.loads(to_sarif(findings, slug_to_path=slug_to_path))
        trifecta = next(r for r in sarif["runs"][0]["results"] if r["ruleId"] == "TRIFLOW-TRIFECTA")
        uri = trifecta["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert uri == "/path/to/config.json"

    def test_finding_without_path_uses_logical_location(self) -> None:
        sarif = json.loads(to_sarif(toxic_findings()))  # no slug_to_path
        result = sarif["runs"][0]["results"][0]
        assert "logicalLocations" in result["locations"][0]

    def test_skill_finding_anchors_to_skill_file(self) -> None:
        findings, _ = lint_skills([SKILLS / "overbroad" / "SKILL.md"])
        sarif = json.loads(to_sarif(findings))
        loc = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        assert "overbroad" in loc["artifactLocation"]["uri"]

    def test_line_region_emitted_when_present(self) -> None:
        finding = Finding(
            rule_id="TRIFLOW-SKILL-MISSING-SCOPING",
            finding_type=FindingType.SKILL_MISSING_SCOPING,
            severity=Severity.MEDIUM,
            title="t",
            detail="d",
            remediation="r",
            location=FileLocation(path="x/SKILL.md", line=7),
        )
        sarif = json.loads(to_sarif((finding,)))
        region = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
        assert region["startLine"] == 7


class TestCatalog:
    def test_every_finding_type_has_a_rule_doc(self) -> None:
        documented = {r.finding_type for r in FINDING_RULES}
        assert documented == set(FindingType)

    def test_level_mapping_covers_all_severities(self) -> None:
        assert set(_LEVEL) == set(Severity)

    def test_rules_by_id_lookup(self) -> None:
        assert RULES_BY_ID["TRIFLOW-TRIFECTA"].default_severity is Severity.CRITICAL


class TestConsole:
    def test_renders_findings_and_fleet(self) -> None:
        recorder = Console(record=True, width=120)
        render_console(toxic_findings(), ("warn one",), servers=toxic_fleet(), console=recorder)
        text = recorder.export_text()
        assert "TRIFLOW-TRIFECTA" in text
        assert "Installed MCP fleet" in text
        assert "warn one" in text

    def test_renders_clean_state(self) -> None:
        recorder = Console(record=True, width=120)
        render_console((), (), servers=benign_fleet(), console=recorder)
        assert "No findings" in recorder.export_text()
