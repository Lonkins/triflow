"""Guardrails that keep docs and packaging honest."""

from __future__ import annotations

import tomllib
from pathlib import Path

import triflow
from triflow.catalog import FINDING_RULES

ROOT = Path(__file__).resolve().parent.parent


def test_every_finding_rule_is_documented() -> None:
    rules_doc = (ROOT / "docs" / "rules.md").read_text(encoding="utf-8")
    for rule in FINDING_RULES:
        assert rule.rule_id in rules_doc, f"{rule.rule_id} missing from docs/rules.md"


def test_package_version_matches_pyproject() -> None:
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert pyproject["project"]["version"] == triflow.__version__


def test_changelog_mentions_current_version() -> None:
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert triflow.__version__ in changelog


def test_every_capability_rule_id_is_referenced_or_prefixed() -> None:
    # Sanity: the rules doc explains each rule-ID prefix used in the catalog.
    rules_doc = (ROOT / "docs" / "rules.md").read_text(encoding="utf-8")
    for prefix in ("PRIV-", "ING-", "EXF-", "STATE-", "EXEC-", "SRV-"):
        assert prefix in rules_doc
