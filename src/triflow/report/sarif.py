"""SARIF 2.1.0 reporter — renders in GitHub code scanning.

Handles both fleet findings (anchored to the relevant server's config file when
resolvable) and skill findings (anchored to the skill file).
"""

from __future__ import annotations

import json

from triflow import __version__
from triflow.catalog import RULES_BY_ID
from triflow.models import Finding, Severity

_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)

_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}
# GitHub code-scanning numeric severity (0-10).
_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "2.0",
}


def _rules_block(findings: tuple[Finding, ...]) -> list[dict[str, object]]:
    rule_ids = sorted({f.rule_id for f in findings})
    rules: list[dict[str, object]] = []
    for rule_id in rule_ids:
        doc = RULES_BY_ID.get(rule_id)
        name = doc.name if doc else rule_id
        summary = doc.summary if doc else rule_id
        help_uri = doc.help_uri if doc else "https://lonkins.github.io/triflow/"
        severity = doc.default_severity if doc else Severity.HIGH
        rules.append(
            {
                "id": rule_id,
                "name": name,
                "shortDescription": {"text": name},
                "fullDescription": {"text": summary},
                "helpUri": help_uri,
                "defaultConfiguration": {"level": _LEVEL[severity]},
                "properties": {"security-severity": _SECURITY_SEVERITY[severity]},
            }
        )
    return rules


def _location_for(finding: Finding, slug_to_path: dict[str, str]) -> str | None:
    if finding.location is not None:
        return finding.location.path
    for participant in reversed(finding.participants):  # sink first
        if participant.server_slug in slug_to_path:
            return slug_to_path[participant.server_slug]
    return None


def _result(finding: Finding, slug_to_path: dict[str, str]) -> dict[str, object]:
    result: dict[str, object] = {
        "ruleId": finding.rule_id,
        "level": _LEVEL[finding.severity],
        "message": {
            "text": f"{finding.title}. {finding.detail} Remediation: {finding.remediation}"
        },
        "properties": {
            "finding_type": finding.finding_type.value,
            "cross_server": finding.cross_server,
            "participants": [p.ref for p in finding.participants],
        },
    }
    path = _location_for(finding, slug_to_path)
    if path is not None:
        physical: dict[str, object] = {"artifactLocation": {"uri": path}}
        if finding.location is not None and finding.location.line is not None:
            physical["region"] = {"startLine": finding.location.line}
        result["locations"] = [{"physicalLocation": physical}]
    else:
        result["locations"] = [
            {"logicalLocations": [{"fullyQualifiedName": s} for s in finding.server_slugs]}
        ]
    return result


def to_sarif(
    findings: tuple[Finding, ...],
    *,
    slug_to_path: dict[str, str] | None = None,
) -> str:
    slug_to_path = slug_to_path or {}
    sarif = {
        "$schema": _SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "triflow",
                        "informationUri": "https://github.com/Lonkins/triflow",
                        "version": __version__,
                        "rules": _rules_block(findings),
                    }
                },
                "results": [_result(f, slug_to_path) for f in findings],
            }
        ],
    }
    return json.dumps(sarif, indent=2)
