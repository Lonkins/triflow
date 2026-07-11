"""Core data models shared across triflow."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Transport(StrEnum):
    """How a client connects to an MCP server."""

    STDIO = "stdio"
    HTTP = "http"
    SSE = "sse"


class ServerConfig(BaseModel):
    """One MCP server as declared in a client config file.

    ``env`` and ``headers`` routinely carry secrets, so they are excluded from
    every serialized dump and repr; they exist in memory only so stdio servers
    can be launched for metadata introspection.
    """

    model_config = ConfigDict(frozen=True)

    name: str
    client: str
    config_path: Path
    transport: Transport
    command: str | None = None
    args: tuple[str, ...] = ()
    env: dict[str, str] = Field(default_factory=dict, exclude=True, repr=False)
    url: str | None = None
    headers: dict[str, str] = Field(default_factory=dict, exclude=True, repr=False)

    @property
    def slug(self) -> str:
        """Stable human-readable identifier, e.g. ``claude-desktop:github``."""
        return f"{self.client}:{self.name}"


class Capability(StrEnum):
    """The capability taxonomy — documented in docs/taxonomy.md."""

    PRIVATE_DATA_SOURCE = "private_data_source"
    UNTRUSTED_CONTENT_INGRESS = "untrusted_content_ingress"
    EXFILTRATION_CHANNEL = "exfiltration_channel"
    STATE_CHANGING = "state_changing"
    CODE_EXECUTION = "code_execution"


class Evidence(BaseModel):
    """Why a capability was assigned: which rule matched what."""

    model_config = ConfigDict(frozen=True)

    rule_id: str
    capability: Capability
    matched_on: str  # tool_name | tool_description | schema_property | server_identity
    pattern: str
    excerpt: str = ""


class ToolInfo(BaseModel):
    """Metadata for one tool as declared by its server. Never the result of
    calling it — triflow does not invoke tools (ADR-0001)."""

    model_config = ConfigDict(frozen=True)

    name: str
    description: str = ""
    input_schema: dict[str, Any] = Field(default_factory=dict)


class IntrospectedServer(BaseModel):
    """A configured server plus whatever metadata introspection produced."""

    model_config = ConfigDict(frozen=True)

    config: ServerConfig
    tools: tuple[ToolInfo, ...] = ()
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None


class ClassifiedTool(BaseModel):
    """A tool plus the capabilities the classifier assigned to it."""

    model_config = ConfigDict(frozen=True)

    server_slug: str
    tool: ToolInfo
    capabilities: frozenset[Capability] = frozenset()
    evidence: tuple[Evidence, ...] = ()


class ClassifiedServer(BaseModel):
    """A server with per-tool and server-level capability assignments.

    ``server_capabilities`` come from rules matching the server's own identity
    (name/command/url) — the offline fallback when tool metadata is missing.
    """

    model_config = ConfigDict(frozen=True)

    config: ServerConfig
    tools: tuple[ClassifiedTool, ...] = ()
    server_capabilities: frozenset[Capability] = frozenset()
    server_evidence: tuple[Evidence, ...] = ()
    introspection_error: str | None = None

    @property
    def slug(self) -> str:
        return self.config.slug

    @property
    def all_capabilities(self) -> frozenset[Capability]:
        merged: frozenset[Capability] = self.server_capabilities
        for tool in self.tools:
            merged = merged | tool.capabilities
        return merged


class Severity(StrEnum):
    """Finding severity, ordered by :data:`SEVERITY_ORDER`."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
}


class FindingType(StrEnum):
    LETHAL_TRIFECTA = "lethal_trifecta"
    TOOL_SHADOWING = "tool_shadowing"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    SKILL_UNBOUNDED_SHELL = "skill_unbounded_shell"
    SKILL_NETWORK_AND_SECRETS = "skill_network_and_secrets"
    SKILL_MISSING_SCOPING = "skill_missing_scoping"
    SKILL_OVERBROAD_TOOLS = "skill_overbroad_tools"


class FileLocation(BaseModel):
    """Where a finding lives on disk (for SARIF physical locations)."""

    model_config = ConfigDict(frozen=True)

    path: str
    line: int | None = None


class Participant(BaseModel):
    """One party to a finding: a specific tool, or a server's own identity when
    the capability came from an identity rule (``tool_name is None``)."""

    model_config = ConfigDict(frozen=True)

    server_slug: str
    tool_name: str | None = None
    capability: Capability | None = None
    role: str = ""

    @property
    def ref(self) -> str:
        base = (
            self.server_slug if self.tool_name is None else f"{self.server_slug}/{self.tool_name}"
        )
        return f"{base} [{self.capability}]" if self.capability else base


class Finding(BaseModel):
    """A composed cross-server risk. ``rule_id`` is stable for SARIF/suppression."""

    model_config = ConfigDict(frozen=True)

    rule_id: str
    finding_type: FindingType
    severity: Severity
    title: str
    detail: str
    remediation: str
    participants: tuple[Participant, ...] = ()
    cross_server: bool = True
    location: FileLocation | None = None

    @property
    def server_slugs(self) -> tuple[str, ...]:
        seen: dict[str, None] = {}
        for participant in self.participants:
            seen.setdefault(participant.server_slug, None)
        return tuple(seen)


class ScanReport(BaseModel):
    """Everything one scan produced: classified fleet, findings, warnings."""

    model_config = ConfigDict(frozen=True)

    servers: tuple[ClassifiedServer, ...] = ()
    findings: tuple[Finding, ...] = ()
    warnings: tuple[str, ...] = ()

    @property
    def server_count(self) -> int:
        return len(self.servers)

    def findings_by_severity(self, severity: Severity) -> tuple[Finding, ...]:
        return tuple(f for f in self.findings if f.severity == severity)
