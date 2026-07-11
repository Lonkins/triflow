"""Safe, metadata-only introspection of configured MCP servers.

The only requests this module ever sends are ``initialize`` and ``tools/list``
(plus the protocol-required ``notifications/initialized``). Anything more is a
security bug, not a feature request — see ADR-0001 and SECURITY.md.

Safety measures for stdio servers:

- launched with a *minimized* environment: the MCP SDK's safe default set
  (PATH, HOME, ...) plus only the env vars the config explicitly declares for
  that server — the scanner's own environment (and its secrets) never leak in;
- hard wall-clock timeout around connect + handshake + listing, after which
  the subprocess tree is terminated;
- no shell involved: ``command`` + ``args`` are executed directly.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterable
from contextlib import asynccontextmanager
from datetime import timedelta

import anyio
from mcp import ClientSession, StdioServerParameters
from mcp.client.sse import sse_client
from mcp.client.stdio import get_default_environment, stdio_client
from mcp.client.streamable_http import streamablehttp_client

from triflow.models import IntrospectedServer, ServerConfig, ToolInfo, Transport

DEFAULT_TIMEOUT_SECONDS = 15.0


class IntrospectionError(Exception):
    """A server could not be introspected (bad config, dead process, ...)."""


def _stdio_params(config: ServerConfig) -> StdioServerParameters:
    if not config.command:
        raise IntrospectionError(f"{config.slug}: stdio server has no command")
    env = {**get_default_environment(), **config.env}
    return StdioServerParameters(command=config.command, args=list(config.args), env=env)


@asynccontextmanager
async def _open_session(config: ServerConfig, timeout: float) -> AsyncIterator[ClientSession]:
    read_timeout = timedelta(seconds=timeout)
    if config.transport is Transport.STDIO:
        async with (
            stdio_client(_stdio_params(config)) as (read, write),
            ClientSession(read, write, read_timeout_seconds=read_timeout) as session,
        ):
            yield session
        return
    if not config.url:
        raise IntrospectionError(f"{config.slug}: {config.transport} server has no url")
    headers = dict(config.headers) or None
    if config.transport is Transport.SSE:
        async with (
            sse_client(config.url, headers=headers) as (read, write),
            ClientSession(read, write, read_timeout_seconds=read_timeout) as session,
        ):
            yield session
        return
    async with (
        streamablehttp_client(config.url, headers=headers) as (read, write, _),
        ClientSession(read, write, read_timeout_seconds=read_timeout) as session,
    ):
        yield session


async def list_tools_metadata(session: ClientSession) -> tuple[ToolInfo, ...]:
    """Handshake and list tool metadata. This function is the entire protocol
    surface of triflow; do not add requests here (ADR-0001)."""
    await session.initialize()
    tools: list[ToolInfo] = []
    cursor: str | None = None
    while True:
        result = await session.list_tools(cursor=cursor)
        tools.extend(
            ToolInfo(
                name=tool.name,
                description=tool.description or "",
                input_schema=tool.inputSchema or {},
            )
            for tool in result.tools
        )
        cursor = result.nextCursor
        if cursor is None:
            return tuple(tools)


async def introspect_server(
    config: ServerConfig, *, timeout: float = DEFAULT_TIMEOUT_SECONDS
) -> IntrospectedServer:
    """Introspect one server; failures become data, never exceptions."""
    try:
        with anyio.fail_after(timeout):
            async with _open_session(config, timeout) as session:
                tools = await list_tools_metadata(session)
        return IntrospectedServer(config=config, tools=tools)
    except TimeoutError:
        return IntrospectedServer(config=config, error=f"timed out after {timeout}s")
    except Exception as exc:  # any single server must not kill the fleet scan
        return IntrospectedServer(config=config, error=f"{type(exc).__name__}: {exc}")


async def introspect_fleet(
    configs: Iterable[ServerConfig], *, timeout: float = DEFAULT_TIMEOUT_SECONDS
) -> tuple[IntrospectedServer, ...]:
    """Introspect servers one at a time — deliberate: no subprocess storm,
    and one hung server cannot starve the others thanks to per-server timeouts."""
    return tuple([await introspect_server(c, timeout=timeout) for c in configs])
