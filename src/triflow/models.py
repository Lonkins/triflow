"""Core data models shared across triflow."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path

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
