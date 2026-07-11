"""Linter for agent ``SKILL.md`` files.

Skills declare capabilities in YAML frontmatter (chiefly ``allowed-tools``).
This linter flags dangerous *declared* posture — it does not execute skills:

- unbounded shell grants (``Bash`` with no argument scoping);
- network egress and secret access granted together (data-theft posture);
- missing ``allowed-tools`` (the skill inherits every tool);
- over-broad grants (wildcards).

A skill file or a directory tree of skills can be linted; frontmatter is parsed
with ``yaml.safe_load`` only.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from pathlib import Path

import yaml

from triflow.models import SEVERITY_ORDER, FileLocation, Finding, FindingType, Severity

_FRONTMATTER = re.compile(r"^---\s*\n(.*?)\n---\s*\n", re.DOTALL)

# A Bash grant is scoped when it carries a non-wildcard argument pattern, e.g.
# ``Bash(git status:*)``. Bare ``Bash`` or ``Bash(*)`` / ``Bash(:*)`` are not.
_BASH_GRANT = re.compile(r"^bash(?:\((?P<arg>.*)\))?$", re.IGNORECASE)
_WILDCARD_ARG = re.compile(r"^\s*:?\*?\s*$")

_WILDCARD_TOOLS = {"*", "all", "any", "*:*"}

_NETWORK_TOOLS = re.compile(
    r"webfetch|websearch|fetch|http|curl|wget|browser|request|url", re.IGNORECASE
)
_SECRET_TOKENS = re.compile(
    r"secret|credential|token|password|api[_-]?key|\.env|keychain|vault", re.IGNORECASE
)
_SHELL_TOOLS = re.compile(r"shell|exec|command|terminal|subprocess", re.IGNORECASE)


def _split_frontmatter(text: str) -> tuple[dict[str, object] | None, str, str | None]:
    """Return (frontmatter, body, warning). Missing/invalid frontmatter is a
    warning, not a crash."""
    match = _FRONTMATTER.match(text)
    if match is None:
        return None, text, "no YAML frontmatter found"
    try:
        data = yaml.safe_load(match.group(1))
    except yaml.YAMLError as exc:
        return None, text, f"invalid YAML frontmatter ({exc})"
    if not isinstance(data, dict):
        return None, text, "frontmatter is not a mapping"
    return data, text[match.end() :], None


def _allowed_tools(frontmatter: dict[str, object]) -> list[str] | None:
    """Normalize the tool grant to a list of strings, or ``None`` if the field
    is absent entirely (distinct from an explicit empty list)."""
    for key in ("allowed-tools", "allowed_tools", "tools"):
        if key in frontmatter:
            value = frontmatter[key]
            if isinstance(value, str):
                return [item.strip() for item in value.split(",") if item.strip()]
            if isinstance(value, list):
                return [str(item).strip() for item in value if str(item).strip()]
            return []
    return None


def _skill_name(frontmatter: dict[str, object] | None, path: Path) -> str:
    if frontmatter and isinstance(frontmatter.get("name"), str):
        return str(frontmatter["name"])
    return path.parent.name if path.name.lower() == "skill.md" else path.stem


def _bash_is_unbounded(grant: str) -> bool:
    match = _BASH_GRANT.match(grant.strip())
    if match is None:
        return False
    arg = match.group("arg")
    return arg is None or _WILDCARD_ARG.match(arg) is not None


def _finding(
    finding_type: FindingType,
    severity: Severity,
    title: str,
    detail: str,
    remediation: str,
    path: Path,
) -> Finding:
    return Finding(
        rule_id=f"TRIFLOW-{finding_type.value.upper().replace('_', '-')}",
        finding_type=finding_type,
        severity=severity,
        title=title,
        detail=detail,
        remediation=remediation,
        cross_server=False,
        location=FileLocation(path=str(path)),
    )


def lint_skill_text(text: str, path: Path) -> tuple[list[Finding], list[str]]:
    frontmatter, body, warning = _split_frontmatter(text)
    warnings = [f"{path}: {warning}"] if warning else []
    if frontmatter is None:
        return [], warnings

    name = _skill_name(frontmatter, path)
    tools = _allowed_tools(frontmatter)
    findings: list[Finding] = []

    if tools is None:
        findings.append(
            _finding(
                FindingType.SKILL_MISSING_SCOPING,
                Severity.MEDIUM,
                f"Skill {name!r} declares no allowed-tools",
                (
                    f"Skill {name!r} has no allowed-tools field, so it inherits every "
                    "tool the agent has, including shell and network access."
                ),
                "Add an allowed-tools list granting only the tools this skill needs.",
                path,
            )
        )
        tools = []

    lowered = [t.lower() for t in tools]

    if any(t in _WILDCARD_TOOLS for t in lowered):
        findings.append(
            _finding(
                FindingType.SKILL_OVERBROAD_TOOLS,
                Severity.HIGH,
                f"Skill {name!r} grants all tools via wildcard",
                (
                    f"Skill {name!r} lists a wildcard tool grant ({', '.join(tools)}), "
                    "which is equivalent to no scoping at all."
                ),
                "Replace the wildcard with the explicit tools this skill needs.",
                path,
            )
        )

    if any(_bash_is_unbounded(t) for t in tools) or _SHELL_TOOLS.search(" ".join(tools)):
        findings.append(
            _finding(
                FindingType.SKILL_UNBOUNDED_SHELL,
                Severity.HIGH,
                f"Skill {name!r} grants unbounded shell access",
                (
                    f"Skill {name!r} grants shell execution without argument scoping. "
                    "An unbounded Bash grant lets a skill run any command, subsuming "
                    "every other capability."
                ),
                "Scope Bash grants to specific commands, e.g. Bash(git status:*).",
                path,
            )
        )

    # Network + secret access together — data theft posture. Consider both the
    # declared tools and the skill body (secrets are often named in prose).
    grants_text = " ".join(tools)
    has_network = bool(_NETWORK_TOOLS.search(grants_text))
    has_secrets = bool(_SECRET_TOKENS.search(grants_text) or _SECRET_TOKENS.search(body))
    if has_network and has_secrets:
        findings.append(
            _finding(
                FindingType.SKILL_NETWORK_AND_SECRETS,
                Severity.HIGH,
                f"Skill {name!r} combines network egress with secret access",
                (
                    f"Skill {name!r} can both reach the network and touch secrets or "
                    "credentials. Together these form an exfiltration path: secrets "
                    "read in one step can be sent out in another."
                ),
                "Split network and secret-handling into separate, scoped skills, or "
                "remove one capability.",
                path,
            )
        )

    return findings, warnings


def lint_skill_file(path: Path) -> tuple[list[Finding], list[str]]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return [], [f"{path}: unreadable ({exc})"]
    return lint_skill_text(text, path)


def discover_skill_files(root: Path) -> list[Path]:
    """A single file, or every ``SKILL.md`` under a directory (sorted)."""
    if root.is_file():
        return [root]
    if root.is_dir():
        return sorted(root.rglob("SKILL.md")) + sorted(root.rglob("skill.md"))
    return []


def lint_skills(paths: Iterable[Path]) -> tuple[tuple[Finding, ...], tuple[str, ...]]:
    findings: list[Finding] = []
    warnings: list[str] = []
    for root in paths:
        files = discover_skill_files(root)
        if not files:
            warnings.append(f"{root}: no SKILL.md found")
        for file in files:
            file_findings, file_warnings = lint_skill_file(file)
            findings.extend(file_findings)
            warnings.extend(file_warnings)
    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], str(f.location), f.rule_id))
    return tuple(findings), tuple(warnings)
