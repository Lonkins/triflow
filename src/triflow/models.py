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
