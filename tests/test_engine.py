from __future__ import annotations

import pytest

from tests.fleet_fixtures import (
    benign_fleet,
    escalation_fleet,
    shadowing_fleet,
    single_server_trifecta_fleet,
    toxic_fleet,
)
from triflow.engine import (
    analyze,
    detect_escalation,
    detect_shadowing,
    detect_trifecta,
)
from triflow.models import FindingType, Severity


class TestTrifecta:
    def test_cross_server_trifecta_names_a_to_b_to_c(self) -> None:
        finding = detect_trifecta(toxic_fleet())
        assert finding is not None
        assert finding.finding_type is FindingType.LETHAL_TRIFECTA
        assert finding.severity is Severity.CRITICAL
        assert finding.cross_server is True
        # the chain must name the three distinct servers
        assert set(finding.server_slugs) == {"test:files", "test:web", "test:mailer"}
        # representative chain reads files → web → mailer tools
        refs = {p.ref for p in finding.participants}
        assert any("read_file" in r for r in refs)
        assert any("fetch_url" in r for r in refs)
        assert any("send_email" in r for r in refs)

    def test_benign_fleet_has_no_trifecta(self) -> None:
        assert detect_trifecta(benign_fleet()) is None

    def test_single_server_trifecta_flagged_but_not_cross_server(self) -> None:
        finding = detect_trifecta(single_server_trifecta_fleet())
        assert finding is not None
        assert finding.cross_server is False
        assert set(finding.server_slugs) == {"test:kitchen-sink"}
        assert "within a single server" in finding.detail

    def test_missing_one_leg_is_clean(self) -> None:
        # drop the mailer: no exfiltration leg left
        fleet = tuple(s for s in toxic_fleet() if s.config.name != "mailer")
        assert detect_trifecta(fleet) is None


class TestShadowing:
    def test_detects_name_collision(self) -> None:
        findings = detect_shadowing(shadowing_fleet())
        search = [f for f in findings if "'search'" in f.title]
        assert len(search) == 1
        finding = search[0]
        assert finding.finding_type is FindingType.TOOL_SHADOWING
        assert set(finding.server_slugs) == {"test:corp", "test:randomplugin"}

    def test_no_false_collision_in_benign_fleet(self) -> None:
        assert detect_shadowing(benign_fleet()) == []

    def test_same_name_within_one_server_is_not_shadowing(self) -> None:
        # toxic_fleet has distinct names per server; no collisions
        assert detect_shadowing(toxic_fleet()) == []

    def test_dangerous_capability_collision_is_high(self) -> None:
        # 'search' is benign-capability so MEDIUM; craft a dangerous collision
        from tests.fleet_fixtures import _server, _stdio
        from triflow.classify import classify_fleet
        from triflow.models import ToolInfo

        a = _server(_stdio("a", "a-mcp"), ToolInfo(name="deploy", description="Deploy the app."))
        b = _server(
            _stdio("b", "b-mcp"), ToolInfo(name="deploy", description="Deploy to production.")
        )
        findings = detect_shadowing(classify_fleet([a, b]))
        assert findings and findings[0].severity is Severity.HIGH


class TestEscalation:
    def test_ingress_to_exec_across_servers(self) -> None:
        findings = detect_escalation(escalation_fleet())
        assert len(findings) == 1
        finding = findings[0]
        assert finding.finding_type is FindingType.PRIVILEGE_ESCALATION
        assert finding.severity is Severity.CRITICAL
        assert finding.server_slugs == ("test:web", "test:shell")
        assert "remote code execution" in finding.detail

    def test_no_escalation_without_executor(self) -> None:
        assert detect_escalation(toxic_fleet()) == []

    def test_no_escalation_when_exec_and_ingress_same_server(self) -> None:
        from tests.fleet_fixtures import _server, _stdio
        from triflow.classify import classify_fleet
        from triflow.models import ToolInfo

        one = _server(
            _stdio("solo", "solo-mcp"),
            ToolInfo(name="fetch_url", description="Fetch a web page."),
            ToolInfo(name="run_command", description="Run a shell command."),
        )
        assert detect_escalation(classify_fleet([one])) == []


class TestAnalyze:
    def test_orders_by_severity(self) -> None:
        findings = analyze(shadowing_fleet())
        severities = [f.severity for f in findings]
        assert severities == sorted(severities, key=lambda s: list(Severity).index(s))

    def test_toxic_fleet_produces_trifecta(self) -> None:
        findings = analyze(toxic_fleet())
        assert any(f.finding_type is FindingType.LETHAL_TRIFECTA for f in findings)

    def test_benign_fleet_is_clean(self) -> None:
        assert analyze(benign_fleet()) == ()

    @pytest.mark.parametrize("fleet_builder", [toxic_fleet, escalation_fleet, shadowing_fleet])
    def test_findings_are_frozen_and_have_remediation(self, fleet_builder) -> None:  # type: ignore[no-untyped-def]
        for finding in analyze(fleet_builder()):
            assert finding.remediation
            assert finding.participants
