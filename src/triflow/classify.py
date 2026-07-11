"""Deterministic capability classification.

Rules live in ``data/capability_rules.yaml`` (documented in docs/rules.md).
Everything here is pure string/regex matching over metadata — no network, no
execution, no model calls. The optional local-LLM assist is a separate,
opt-in module layered on top of these results, never a replacement.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import cache
from importlib import resources

import yaml
from pydantic import BaseModel, ConfigDict

from triflow.models import (
    Capability,
    ClassifiedServer,
    ClassifiedTool,
    Evidence,
    IntrospectedServer,
    ServerConfig,
    ToolInfo,
)

_EXCERPT_LEN = 80


class RuleSpec(BaseModel):
    """Schema-validated shape of one YAML rule entry."""

    model_config = ConfigDict(frozen=True)

    id: str
    capability: Capability
    rationale: str
    name_patterns: tuple[str, ...] = ()
    description_patterns: tuple[str, ...] = ()
    schema_property_patterns: tuple[str, ...] = ()
    server_patterns: tuple[str, ...] = ()


class RuleCatalog(BaseModel):
    model_config = ConfigDict(frozen=True)

    rules: tuple[RuleSpec, ...]


@dataclass(frozen=True)
class Rule:
    """A rule with its regexes compiled once."""

    spec: RuleSpec
    name_res: tuple[re.Pattern[str], ...] = field(default=())
    description_res: tuple[re.Pattern[str], ...] = field(default=())
    schema_property_res: tuple[re.Pattern[str], ...] = field(default=())
    server_res: tuple[re.Pattern[str], ...] = field(default=())

    @classmethod
    def compile(cls, spec: RuleSpec) -> Rule:
        def compile_all(patterns: tuple[str, ...]) -> tuple[re.Pattern[str], ...]:
            return tuple(re.compile(p) for p in patterns)

        return cls(
            spec=spec,
            name_res=compile_all(spec.name_patterns),
            description_res=compile_all(spec.description_patterns),
            schema_property_res=compile_all(spec.schema_property_patterns),
            server_res=compile_all(spec.server_patterns),
        )


@cache
def load_rules() -> tuple[Rule, ...]:
    """Load and compile the packaged rule catalog (cached)."""
    raw = resources.files("triflow.data").joinpath("capability_rules.yaml").read_text("utf-8")
    catalog = RuleCatalog.model_validate(yaml.safe_load(raw))
    return tuple(Rule.compile(spec) for spec in catalog.rules)


def _excerpt(text: str, match: re.Match[str]) -> str:
    start = max(0, match.start() - 20)
    return text[start : start + _EXCERPT_LEN]


def _match_evidence(rule: Rule, tool: ToolInfo) -> Evidence | None:
    name = tool.name.lower()
    for pattern in rule.name_res:
        if m := pattern.search(name):
            return Evidence(
                rule_id=rule.spec.id,
                capability=rule.spec.capability,
                matched_on="tool_name",
                pattern=pattern.pattern,
                excerpt=_excerpt(name, m),
            )
    description = tool.description.lower()
    for pattern in rule.description_res:
        if m := pattern.search(description):
            return Evidence(
                rule_id=rule.spec.id,
                capability=rule.spec.capability,
                matched_on="tool_description",
                pattern=pattern.pattern,
                excerpt=_excerpt(description, m),
            )
    return None


def _schema_evidence(rule: Rule, tool: ToolInfo) -> Evidence | None:
    """Schema rules require BOTH a name pattern and a schema-property hit —
    a bare ``url`` parameter on an unambiguous tool must not fire alone."""
    if not rule.schema_property_res:
        return None
    name = tool.name.lower()
    if not any(p.search(name) for p in rule.name_res):
        return None
    properties = tool.input_schema.get("properties")
    if not isinstance(properties, dict):
        return None
    for prop in properties:
        prop_name = str(prop).lower()
        for pattern in rule.schema_property_res:
            if pattern.search(prop_name):
                return Evidence(
                    rule_id=rule.spec.id,
                    capability=rule.spec.capability,
                    matched_on="schema_property",
                    pattern=pattern.pattern,
                    excerpt=prop_name,
                )
    return None


def classify_tool(
    tool: ToolInfo, server_slug: str, rules: tuple[Rule, ...] | None = None
) -> ClassifiedTool:
    rules = rules if rules is not None else load_rules()
    evidence: list[Evidence] = []
    for rule in rules:
        if rule.spec.schema_property_patterns:
            found = _schema_evidence(rule, tool)
        else:
            found = _match_evidence(rule, tool)
        if found is not None:
            evidence.append(found)
    return ClassifiedTool(
        server_slug=server_slug,
        tool=tool,
        capabilities=frozenset(e.capability for e in evidence),
        evidence=tuple(evidence),
    )


def _server_identity(config: ServerConfig) -> str:
    parts = [config.name, config.command or "", " ".join(config.args), config.url or ""]
    return " ".join(p for p in parts if p).lower()


def classify_server_identity(
    config: ServerConfig, rules: tuple[Rule, ...] | None = None
) -> tuple[frozenset[Capability], tuple[Evidence, ...]]:
    """Offline fallback: infer capabilities from what the config alone reveals."""
    rules = rules if rules is not None else load_rules()
    identity = _server_identity(config)
    evidence: list[Evidence] = []
    for rule in rules:
        for pattern in rule.server_res:
            if m := pattern.search(identity):
                evidence.append(
                    Evidence(
                        rule_id=rule.spec.id,
                        capability=rule.spec.capability,
                        matched_on="server_identity",
                        pattern=pattern.pattern,
                        excerpt=_excerpt(identity, m),
                    )
                )
                break
    return frozenset(e.capability for e in evidence), tuple(evidence)


def classify_fleet(
    servers: tuple[IntrospectedServer, ...] | list[IntrospectedServer],
    rules: tuple[Rule, ...] | None = None,
) -> tuple[ClassifiedServer, ...]:
    """Classify every server: tool-level where metadata exists, plus
    identity-level fallback signals either way."""
    rules = rules if rules is not None else load_rules()
    classified: list[ClassifiedServer] = []
    for server in servers:
        caps, evidence = classify_server_identity(server.config, rules)
        classified.append(
            ClassifiedServer(
                config=server.config,
                tools=tuple(
                    classify_tool(tool, server.config.slug, rules) for tool in server.tools
                ),
                server_capabilities=caps,
                server_evidence=evidence,
                introspection_error=server.error,
            )
        )
    return tuple(classified)
