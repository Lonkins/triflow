from __future__ import annotations

import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import timedelta
from pathlib import Path
from typing import Any, cast

import anyio
import pytest
from mcp import ClientSession
from mcp.client.stdio import stdio_client
from mcp.server.fastmcp import FastMCP
from mcp.shared.memory import MessageStream, create_client_server_memory_streams
from mcp.shared.message import SessionMessage

from triflow.introspect import (
    _stdio_params,
    introspect_fleet,
    introspect_server,
    list_tools_metadata,
)
from triflow.models import ServerConfig, Transport

FIXTURE_SERVERS = Path(__file__).parent / "fixtures" / "servers"


def stdio_config(tmp_path: Path, sentinel: Path, script: str = "demo_server.py") -> ServerConfig:
    return ServerConfig(
        name="demo",
        client="test",
        config_path=tmp_path / "cfg.json",
        transport=Transport.STDIO,
        command=sys.executable,
        args=(str(FIXTURE_SERVERS / script),),
        env={"TRIFLOW_TEST_SENTINEL": str(sentinel)},
    )


class RecordingStream:
    """Wraps the session write stream and records every JSON-RPC method sent —
    transport-level proof of what triflow actually asks a server to do."""

    def __init__(self, inner: object, methods: list[str]) -> None:
        self._inner = inner
        self._methods = methods

    async def send(self, item: SessionMessage) -> None:
        method = getattr(item.message.root, "method", None)
        if isinstance(method, str):
            self._methods.append(method)
        await cast(Any, self._inner).send(item)

    # dunder lookups bypass __getattr__, and BaseSession uses the write stream
    # as an async context manager — delegate those explicitly
    async def __aenter__(self) -> RecordingStream:
        await cast(Any, self._inner).__aenter__()
        return self

    async def __aexit__(self, *exc: object) -> None:
        await cast(Any, self._inner).__aexit__(*exc)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


class TestStdioIntrospection:
    async def test_lists_tools_without_invoking_any(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("TRIFLOW_ENV_PROBE", "PARENT-ONLY-VALUE")
        sentinel = tmp_path / "sentinel"
        result = await introspect_server(stdio_config(tmp_path, sentinel), timeout=30)
        assert result.ok, result.error
        assert {t.name for t in result.tools} == {"read_notes", "send_email"}
        read_notes = next(t for t in result.tools if t.name == "read_notes")
        # parent environment must NOT leak into the introspected server
        assert "env-probe=absent" in read_notes.description
        assert "PARENT-ONLY-VALUE" not in read_notes.description
        # env declared in the server's own config MUST be passed through
        assert "sentinel=set" in read_notes.description
        # schemas captured
        assert "path" in read_notes.input_schema.get("properties", {})
        # the tripwire: no tool was ever executed
        assert not sentinel.exists()

    async def test_transport_level_method_recording(self, tmp_path: Path) -> None:
        sentinel = tmp_path / "sentinel"
        methods: list[str] = []
        params = _stdio_params(stdio_config(tmp_path, sentinel))
        async with stdio_client(params) as (read, write):
            recording = RecordingStream(write, methods)
            session = ClientSession(
                read, cast(Any, recording), read_timeout_seconds=timedelta(seconds=30)
            )
            async with session:
                tools = await list_tools_metadata(session)
        assert len(tools) == 2
        assert set(methods) == {"initialize", "notifications/initialized", "tools/list"}
        assert "tools/call" not in methods
        assert not sentinel.exists()

    async def test_hard_timeout_on_hung_server(self, tmp_path: Path) -> None:
        config = stdio_config(tmp_path, tmp_path / "s", script="slow_server.py")
        with anyio.move_on_after(20) as scope:
            result = await introspect_server(config, timeout=1.5)
        assert not scope.cancelled_caught, "introspection did not honor its timeout"
        assert result.error is not None and "timed out" in result.error

    async def test_bad_command_is_error_not_crash(self, tmp_path: Path) -> None:
        config = ServerConfig(
            name="ghost",
            client="test",
            config_path=tmp_path / "cfg.json",
            transport=Transport.STDIO,
            command="/nonexistent/triflow-test-binary",
        )
        result = await introspect_server(config, timeout=10)
        assert not result.ok
        assert result.tools == ()

    async def test_stdio_without_command_is_error(self, tmp_path: Path) -> None:
        config = ServerConfig(
            name="empty",
            client="test",
            config_path=tmp_path / "cfg.json",
            transport=Transport.STDIO,
        )
        result = await introspect_server(config, timeout=5)
        assert result.error is not None and "no command" in result.error


def _web_fixture_server() -> FastMCP:
    server = FastMCP("web")

    @server.tool()
    def fetch_page(url: str) -> str:
        """Fetch a web page from the internet."""
        return ""

    return server


@asynccontextmanager
async def _memory_server(server: FastMCP) -> AsyncIterator[MessageStream]:
    async with create_client_server_memory_streams() as (client_streams, server_streams):
        low = server._mcp_server
        async with anyio.create_task_group() as tg:
            tg.start_soon(
                low.run, server_streams[0], server_streams[1], low.create_initialization_options()
            )
            try:
                yield client_streams
            finally:
                tg.cancel_scope.cancel()


class TestHttpTransports:
    async def test_streamable_http_route(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured: dict[str, Any] = {}

        @asynccontextmanager
        async def fake_streamable(
            url: str, headers: dict[str, str] | None = None, **kwargs: Any
        ) -> AsyncIterator[Any]:
            captured["url"], captured["headers"] = url, headers
            async with _memory_server(_web_fixture_server()) as (read, write):
                yield read, write, (lambda: None)

        monkeypatch.setattr("triflow.introspect.streamablehttp_client", fake_streamable)
        config = ServerConfig(
            name="web",
            client="test",
            config_path=tmp_path / "cfg.json",
            transport=Transport.HTTP,
            url="https://example.test/mcp",
            headers={"Authorization": "Bearer FIXTURE-PLACEHOLDER"},
        )
        result = await introspect_server(config, timeout=10)
        assert result.ok, result.error
        assert {t.name for t in result.tools} == {"fetch_page"}
        assert captured["url"] == "https://example.test/mcp"
        assert captured["headers"] == {"Authorization": "Bearer FIXTURE-PLACEHOLDER"}

    async def test_sse_route(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        @asynccontextmanager
        async def fake_sse(
            url: str, headers: dict[str, str] | None = None, **kwargs: Any
        ) -> AsyncIterator[Any]:
            async with _memory_server(_web_fixture_server()) as (read, write):
                yield read, write

        monkeypatch.setattr("triflow.introspect.sse_client", fake_sse)
        config = ServerConfig(
            name="web-sse",
            client="test",
            config_path=tmp_path / "cfg.json",
            transport=Transport.SSE,
            url="https://example.test/sse",
        )
        result = await introspect_server(config, timeout=10)
        assert result.ok, result.error
        assert {t.name for t in result.tools} == {"fetch_page"}

    async def test_http_without_url_is_error(self, tmp_path: Path) -> None:
        config = ServerConfig(
            name="nourl",
            client="test",
            config_path=tmp_path / "cfg.json",
            transport=Transport.HTTP,
        )
        result = await introspect_server(config, timeout=5)
        assert result.error is not None and "no url" in result.error


class TestFleet:
    async def test_one_bad_server_does_not_kill_the_scan(self, tmp_path: Path) -> None:
        good = stdio_config(tmp_path, tmp_path / "sentinel")
        bad = ServerConfig(
            name="ghost",
            client="test",
            config_path=tmp_path / "cfg.json",
            transport=Transport.STDIO,
            command="/nonexistent/triflow-test-binary",
        )
        results = await introspect_fleet([good, bad], timeout=30)
        assert [r.ok for r in results] == [True, False]
        assert not (tmp_path / "sentinel").exists()
