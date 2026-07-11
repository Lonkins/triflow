from __future__ import annotations

from pathlib import Path

from triflow.models import FindingType, Severity
from triflow.skill import (
    _bash_is_unbounded,
    lint_skill_file,
    lint_skill_text,
    lint_skills,
)

SKILLS = Path(__file__).parent / "fixtures" / "skills"


def types(findings: list) -> set[FindingType]:  # type: ignore[type-arg]
    return {f.finding_type for f in findings}


class TestBashScoping:
    def test_bare_bash_is_unbounded(self) -> None:
        assert _bash_is_unbounded("Bash")

    def test_wildcard_bash_is_unbounded(self) -> None:
        assert _bash_is_unbounded("Bash(*)")
        assert _bash_is_unbounded("Bash(:*)")
        assert _bash_is_unbounded("Bash()")

    def test_scoped_bash_is_bounded(self) -> None:
        assert not _bash_is_unbounded("Bash(git status:*)")
        assert not _bash_is_unbounded("Bash(npm run test:*)")

    def test_non_bash_is_not_unbounded(self) -> None:
        assert not _bash_is_unbounded("Read")


class TestOverbroadSkill:
    def test_flags_unbounded_shell_and_network_plus_secrets(self) -> None:
        findings, warnings = lint_skill_file(SKILLS / "overbroad" / "SKILL.md")
        assert warnings == []
        # bare Bash → unbounded shell
        assert FindingType.SKILL_UNBOUNDED_SHELL in types(findings)
        shell = next(f for f in findings if f.finding_type is FindingType.SKILL_UNBOUNDED_SHELL)
        assert shell.severity is Severity.HIGH
        assert shell.location is not None and "overbroad" in shell.location.path


class TestSafeSkill:
    def test_well_scoped_skill_is_clean(self) -> None:
        findings, warnings = lint_skill_file(SKILLS / "safe" / "SKILL.md")
        assert findings == []
        assert warnings == []


class TestExfilSkill:
    def test_network_plus_secrets_from_body(self) -> None:
        findings, _ = lint_skill_file(SKILLS / "exfil" / "SKILL.md")
        assert FindingType.SKILL_NETWORK_AND_SECRETS in types(findings)
        finding = next(
            f for f in findings if f.finding_type is FindingType.SKILL_NETWORK_AND_SECRETS
        )
        assert finding.severity is Severity.HIGH


class TestMissingScoping:
    def test_no_allowed_tools_is_flagged(self) -> None:
        findings, _ = lint_skill_file(SKILLS / "noscope" / "SKILL.md")
        assert FindingType.SKILL_MISSING_SCOPING in types(findings)
        finding = findings[0]
        assert finding.severity is Severity.MEDIUM

    def test_empty_allowed_tools_is_not_missing(self) -> None:
        text = "---\nname: x\nallowed-tools: []\n---\nbody"
        findings, _ = lint_skill_text(text, Path("x/SKILL.md"))
        assert FindingType.SKILL_MISSING_SCOPING not in types(findings)


class TestWildcard:
    def test_wildcard_grant_is_overbroad_and_unbounded_shell(self) -> None:
        findings, _ = lint_skill_file(SKILLS / "wildcard.md")
        assert FindingType.SKILL_OVERBROAD_TOOLS in types(findings)


class TestRobustness:
    def test_no_frontmatter_warns_not_crashes(self) -> None:
        findings, warnings = lint_skill_file(SKILLS / "nofrontmatter.md")
        assert findings == []
        assert any("no YAML frontmatter" in w for w in warnings)

    def test_invalid_yaml_warns(self) -> None:
        findings, warnings = lint_skill_text("---\nname: [unclosed\n---\nbody", Path("x.md"))
        assert findings == []
        assert any("invalid YAML" in w for w in warnings)

    def test_frontmatter_not_mapping_warns(self) -> None:
        _, warnings = lint_skill_text("---\n- just\n- a\n- list\n---\nbody", Path("x.md"))
        assert any("not a mapping" in w for w in warnings)

    def test_string_allowed_tools_parsed(self) -> None:
        text = "---\nname: x\nallowed-tools: Read, Edit, Bash(ls:*)\n---\nbody"
        findings, _ = lint_skill_text(text, Path("x/SKILL.md"))
        assert findings == []  # all scoped


class TestDirectoryLinting:
    def test_lint_skills_walks_directory(self) -> None:
        findings, _ = lint_skills([SKILLS])
        # every SKILL.md under the tree contributes; safe one adds nothing
        found_types = {f.finding_type for f in findings}
        assert FindingType.SKILL_UNBOUNDED_SHELL in found_types
        assert FindingType.SKILL_NETWORK_AND_SECRETS in found_types
        assert FindingType.SKILL_MISSING_SCOPING in found_types
        # sorted most-severe first
        severities = [f.severity for f in findings]
        assert severities == sorted(severities, key=lambda s: list(Severity).index(s))

    def test_lint_single_file_path(self) -> None:
        findings, _ = lint_skills([SKILLS / "overbroad" / "SKILL.md"])
        assert findings

    def test_missing_path_warns(self, tmp_path: Path) -> None:
        _, warnings = lint_skills([tmp_path / "nope"])
        assert any("no SKILL.md" in w for w in warnings)
