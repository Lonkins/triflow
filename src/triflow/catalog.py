"""Static catalog of triflow finding rules — the single source of truth for
SARIF rule metadata and the generated docs rule page."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from triflow.models import FindingType, Severity


class RuleDoc(BaseModel):
    model_config = ConfigDict(frozen=True)

    rule_id: str
    finding_type: FindingType
    name: str
    default_severity: Severity
    summary: str
    help_uri: str


_HELP_BASE = "https://lonkins.github.io/triflow/rules/"

FINDING_RULES: tuple[RuleDoc, ...] = (
    RuleDoc(
        rule_id="TRIFLOW-TRIFECTA",
        finding_type=FindingType.LETHAL_TRIFECTA,
        name="Lethal trifecta",
        default_severity=Severity.CRITICAL,
        summary=(
            "The installed fleet jointly grants private-data access, untrusted-content "
            "ingress, and an exfiltration channel — the three ingredients of a "
            "prompt-injection data-theft attack."
        ),
        help_uri=f"{_HELP_BASE}#lethal-trifecta",
    ),
    RuleDoc(
        rule_id="TRIFLOW-SHADOW",
        finding_type=FindingType.TOOL_SHADOWING,
        name="Tool shadowing",
        default_severity=Severity.HIGH,
        summary=(
            "Two or more servers export a tool with the same name, letting a malicious "
            "server impersonate a trusted one when tools are resolved by bare name."
        ),
        help_uri=f"{_HELP_BASE}#tool-shadowing",
    ),
    RuleDoc(
        rule_id="TRIFLOW-ESCALATE",
        finding_type=FindingType.PRIVILEGE_ESCALATION,
        name="Injection-to-execution chain",
        default_severity=Severity.CRITICAL,
        summary=(
            "One server ingests untrusted content while another can execute code; an "
            "injection in the ingested content becomes cross-server remote code execution."
        ),
        help_uri=f"{_HELP_BASE}#privilege-escalation",
    ),
    RuleDoc(
        rule_id="TRIFLOW-SKILL-UNBOUNDED-SHELL",
        finding_type=FindingType.SKILL_UNBOUNDED_SHELL,
        name="Skill grants unbounded shell",
        default_severity=Severity.HIGH,
        summary="A skill grants Bash with no argument scoping, allowing any command.",
        help_uri=f"{_HELP_BASE}#skill-unbounded-shell",
    ),
    RuleDoc(
        rule_id="TRIFLOW-SKILL-NETWORK-AND-SECRETS",
        finding_type=FindingType.SKILL_NETWORK_AND_SECRETS,
        name="Skill combines network egress with secret access",
        default_severity=Severity.HIGH,
        summary=(
            "A skill can both reach the network and touch secrets, forming an "
            "exfiltration path within a single skill."
        ),
        help_uri=f"{_HELP_BASE}#skill-network-and-secrets",
    ),
    RuleDoc(
        rule_id="TRIFLOW-SKILL-MISSING-SCOPING",
        finding_type=FindingType.SKILL_MISSING_SCOPING,
        name="Skill declares no allowed-tools",
        default_severity=Severity.MEDIUM,
        summary="A skill has no allowed-tools field and inherits every tool the agent has.",
        help_uri=f"{_HELP_BASE}#skill-missing-scoping",
    ),
    RuleDoc(
        rule_id="TRIFLOW-SKILL-OVERBROAD-TOOLS",
        finding_type=FindingType.SKILL_OVERBROAD_TOOLS,
        name="Skill grants tools via wildcard",
        default_severity=Severity.HIGH,
        summary="A skill lists a wildcard tool grant, equivalent to no scoping.",
        help_uri=f"{_HELP_BASE}#skill-overbroad-tools",
    ),
)

RULES_BY_ID: dict[str, RuleDoc] = {rule.rule_id: rule for rule in FINDING_RULES}
