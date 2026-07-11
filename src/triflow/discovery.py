"""Discover MCP servers declared in client config files.

Supports Claude Desktop, Claude Code, Cursor, and Windsurf out of the box.
New clients plug in by implementing the :class:`ConfigSource` protocol.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from triflow.models import ServerConfig, Transport


@dataclass(frozen=True)
class DiscoveryResult:
    """Servers found plus non-fatal problems encountered on the way."""

    servers: tuple[ServerConfig, ...] = ()
    warnings: tuple[str, ...] = ()

    def merge(self, other: DiscoveryResult) -> DiscoveryResult:
        return DiscoveryResult(
            servers=self.servers + other.servers,
            warnings=self.warnings + other.warnings,
        )


@runtime_checkable
class ConfigSource(Protocol):
    """A place MCP server configs can live. Implementations never raise on
    missing or malformed files — problems surface as warnings."""

    @property
    def client(self) -> str: ...

    def discover(self) -> DiscoveryResult: ...


def _load_json(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    if not path.is_file():
        return None, None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return None, f"{path}: unreadable config ({exc})"
    if not isinstance(data, dict):
        return None, f"{path}: expected a JSON object at top level"
    return data, None


def _parse_server(
    name: str, spec: object, client: str, path: Path
) -> tuple[ServerConfig | None, str | None]:
    if not isinstance(spec, Mapping):
        return None, f"{path}: server {name!r} is not an object"
    url = spec.get("url") or spec.get("serverUrl")
    command = spec.get("command")
    declared_type = str(spec.get("type", "")).lower()
    if command:
        transport = Transport.STDIO
    elif url:
        transport = Transport.SSE if declared_type == "sse" else Transport.HTTP
    else:
        return None, f"{path}: server {name!r} has neither command nor url"
    args = spec.get("args", [])
    env = spec.get("env", {})
    headers = spec.get("headers", {})
    if (
        not isinstance(args, list)
        or not isinstance(env, Mapping)
        or not isinstance(headers, Mapping)
    ):
        return None, f"{path}: server {name!r} has malformed args/env/headers"
    return (
        ServerConfig(
            name=name,
            client=client,
            config_path=path,
            transport=transport,
            command=str(command) if command else None,
            args=tuple(str(a) for a in args),
            env={str(k): str(v) for k, v in env.items()},
            url=str(url) if url else None,
            headers={str(k): str(v) for k, v in headers.items()},
        ),
        None,
    )


def _parse_servers_map(servers: object, client: str, path: Path) -> DiscoveryResult:
    if not isinstance(servers, Mapping):
        return DiscoveryResult(warnings=(f"{path}: mcpServers is not an object",))
    found: list[ServerConfig] = []
    warnings: list[str] = []
    for name, spec in servers.items():
        server, warning = _parse_server(str(name), spec, client, path)
        if server is not None:
            found.append(server)
        if warning is not None:
            warnings.append(warning)
    return DiscoveryResult(servers=tuple(found), warnings=tuple(warnings))


def _discover_mcp_servers_files(client: str, paths: Iterable[Path]) -> DiscoveryResult:
    """Shared path for configs shaped ``{"mcpServers": {name: spec}}``."""
    result = DiscoveryResult()
    for path in paths:
        data, warning = _load_json(path)
        if warning is not None:
            result = result.merge(DiscoveryResult(warnings=(warning,)))
        if data is None:
            continue
        result = result.merge(_parse_servers_map(data.get("mcpServers", {}), client, path))
    return result


@dataclass(frozen=True)
class ClaudeDesktopSource:
    home: Path
    platform: str = sys.platform
    client: str = "claude-desktop"

    def config_path(self) -> Path:
        if self.platform == "darwin":
            return (
                self.home
                / "Library"
                / "Application Support"
                / "Claude"
                / ("claude_desktop_config.json")
            )
        if self.platform.startswith("win"):
            return self.home / "AppData" / "Roaming" / "Claude" / "claude_desktop_config.json"
        return self.home / ".config" / "Claude" / "claude_desktop_config.json"

    def discover(self) -> DiscoveryResult:
        return _discover_mcp_servers_files(self.client, [self.config_path()])


@dataclass(frozen=True)
class ClaudeCodeSource:
    """Claude Code: global ``~/.claude.json`` (top-level and per-project
    ``mcpServers``) plus the project-scoped ``.mcp.json``."""

    home: Path
    project: Path
    client: str = "claude-code"

    def discover(self) -> DiscoveryResult:
        result = _discover_mcp_servers_files(self.client, [self.project / ".mcp.json"])
        global_path = self.home / ".claude.json"
        data, warning = _load_json(global_path)
        if warning is not None:
            result = result.merge(DiscoveryResult(warnings=(warning,)))
        if data is None:
            return result
        result = result.merge(
            _parse_servers_map(data.get("mcpServers", {}), self.client, global_path)
        )
        projects = data.get("projects", {})
        if isinstance(projects, Mapping):
            for project_settings in projects.values():
                if isinstance(project_settings, Mapping):
                    result = result.merge(
                        _parse_servers_map(
                            project_settings.get("mcpServers", {}), self.client, global_path
                        )
                    )
        return result


@dataclass(frozen=True)
class CursorSource:
    home: Path
    project: Path
    client: str = "cursor"

    def discover(self) -> DiscoveryResult:
        return _discover_mcp_servers_files(
            self.client,
            [self.home / ".cursor" / "mcp.json", self.project / ".cursor" / "mcp.json"],
        )


@dataclass(frozen=True)
class WindsurfSource:
    home: Path
    client: str = "windsurf"

    def discover(self) -> DiscoveryResult:
        return _discover_mcp_servers_files(
            self.client, [self.home / ".codeium" / "windsurf" / "mcp_config.json"]
        )


def default_sources(home: Path | None = None, project: Path | None = None) -> list[ConfigSource]:
    home = home or Path.home()
    project = project or Path.cwd()
    return [
        ClaudeDesktopSource(home=home),
        ClaudeCodeSource(home=home, project=project),
        CursorSource(home=home, project=project),
        WindsurfSource(home=home),
    ]


def discover_fleet(sources: Iterable[ConfigSource]) -> DiscoveryResult:
    """Run every source and combine results into one fleet view."""
    result = DiscoveryResult()
    for source in sources:
        result = result.merge(source.discover())
    return result
