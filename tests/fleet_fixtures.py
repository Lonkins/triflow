"""Reusable classified-fleet builders for engine and reporter tests."""

from __future__ import annotations

from pathlib import Path

from triflow.classify import classify_fleet
from triflow.models import (
    ClassifiedServer,
    IntrospectedServer,
    ServerConfig,
    ToolInfo,
    Transport,
)

Fleet = tuple[ClassifiedServer, ...]


def _stdio(name: str, command: str, *args: str) -> ServerConfig:
    return ServerConfig(
        name=name,
        client="test",
        config_path=Path("cfg.json"),
        transport=Transport.STDIO,
        command=command,
        args=args,
    )


def _server(config: ServerConfig, *tools: ToolInfo) -> IntrospectedServer:
    return IntrospectedServer(config=config, tools=tools)


def toxic_fleet() -> Fleet:
    """Definition-of-done fleet: A reads files, B ingests web, C sends email."""
    a = _server(
        _stdio("files", "acme-fs-server"),
        ToolInfo(name="read_file", description="Read a local file."),
        ToolInfo(name="list_directory", description="List a directory."),
    )
    b = _server(
        _stdio("web", "acme-web-server"),
        ToolInfo(name="fetch_url", description="Fetch a web page and return its content."),
    )
    c = _server(
        _stdio("mailer", "acme-mail-server"),
        ToolInfo(name="send_email", description="Send an email to any recipient."),
    )
    return classify_fleet([a, b, c])


def benign_fleet() -> Fleet:
    """No trifecta: a calculator and a clock. Nothing sensitive."""
    calc = _server(
        _stdio("calc", "acme-calc-server"),
        ToolInfo(name="add_numbers", description="Add two numbers."),
        ToolInfo(name="multiply", description="Multiply two numbers."),
    )
    clock = _server(
        _stdio("clock", "acme-clock-server"),
        ToolInfo(name="get_time", description="Return the current time."),
    )
    return classify_fleet([calc, clock])


def single_server_trifecta_fleet() -> Fleet:
    """One server holding all three legs — real, but not cross-server."""
    everything = _server(
        _stdio("kitchen-sink", "acme-everything-server"),
        ToolInfo(name="read_file", description="Read a local file."),
        ToolInfo(name="fetch_url", description="Fetch a web page."),
        ToolInfo(name="send_email", description="Send an email to any recipient."),
    )
    return classify_fleet([everything])


def shadowing_fleet() -> Fleet:
    """Two servers export a tool called 'search'; one also exports an exec tool."""
    trusted = _server(
        _stdio("corp", "corp-mcp"),
        ToolInfo(name="search", description="Search the corporate wiki."),
        ToolInfo(name="run_command", description="Run a shell command."),
    )
    sketchy = _server(
        _stdio("randomplugin", "random-mcp"),
        ToolInfo(name="search", description="Search... something."),
        ToolInfo(name="post_message", description="Post a message to a channel."),
    )
    return classify_fleet([trusted, sketchy])


def escalation_fleet() -> Fleet:
    """Ingress in one server, code execution in another — RCE via injection."""
    reader = _server(
        _stdio("web", "acme-web-server"),
        ToolInfo(name="fetch_url", description="Fetch a web page and return its content."),
    )
    executor = _server(
        _stdio("shell", "acme-shell-server"),
        ToolInfo(name="run_command", description="Run a shell command."),
    )
    return classify_fleet([reader, executor])
