"""Typer CLI: ``scan`` the MCP fleet, ``lint-skills``, ``rules``, ``version``."""

from __future__ import annotations

import asyncio
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from triflow import __version__
from triflow.catalog import FINDING_RULES
from triflow.discovery import (
    DiscoveryResult,
    _load_json,
    _parse_servers_map,
    default_sources,
    discover_fleet,
)
from triflow.introspect import DEFAULT_TIMEOUT_SECONDS
from triflow.llm import OllamaBackend
from triflow.models import SEVERITY_ORDER, ClassifiedServer, Finding, Severity
from triflow.report import render_console, to_json, to_sarif
from triflow.scan import scan_configs
from triflow.skill import lint_skills

app = typer.Typer(
    name="triflow",
    help="Cross-server MCP toxic-flow analyzer and SKILL.md linter.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()
err_console = Console(stderr=True)


class OutputFormat(StrEnum):
    CLI = "cli"
    JSON = "json"
    SARIF = "sarif"


@app.callback()
def main() -> None:
    """Cross-server MCP toxic-flow analyzer and SKILL.md linter."""


def _slug_to_path(servers: tuple[ClassifiedServer, ...]) -> dict[str, str]:
    return {s.slug: str(s.config.config_path) for s in servers}


def _at_or_above(findings: tuple[Finding, ...], threshold: Severity) -> bool:
    limit = SEVERITY_ORDER[threshold]
    return any(SEVERITY_ORDER[f.severity] <= limit for f in findings)


def _emit(
    findings: tuple[Finding, ...],
    warnings: tuple[str, ...],
    output_format: OutputFormat,
    output: Path | None,
    *,
    servers: tuple[ClassifiedServer, ...] | None = None,
) -> None:
    if output_format is OutputFormat.CLI:
        render_console(findings, warnings, servers=servers, console=console)
        return
    if output_format is OutputFormat.JSON:
        text = to_json(findings, warnings, servers=servers)
    else:
        slug_to_path = _slug_to_path(servers) if servers is not None else {}
        text = to_sarif(findings, slug_to_path=slug_to_path)
    if output is not None:
        output.write_text(text + "\n", encoding="utf-8")
        err_console.print(f"[green]wrote {output_format.value} to {output}[/green]")
    else:
        # Bypass rich: line-wrapping would corrupt JSON/SARIF string values.
        typer.echo(text)


@app.command()
def scan(
    config: Annotated[
        list[Path] | None,
        typer.Option("--config", "-c", help="Explicit MCP config file(s); repeatable."),
    ] = None,
    home: Annotated[
        Path | None, typer.Option(help="Home dir for auto-discovery (default: real home).")
    ] = None,
    project: Annotated[
        Path | None, typer.Option(help="Project dir for auto-discovery (default: cwd).")
    ] = None,
    introspect: Annotated[
        bool,
        typer.Option(
            "--introspect/--no-introspect",
            help="Launch servers for metadata-only tool listing (never invokes tools).",
        ),
    ] = True,
    timeout: Annotated[
        float, typer.Option(help="Per-server introspection timeout (seconds).")
    ] = DEFAULT_TIMEOUT_SECONDS,
    llm: Annotated[
        bool, typer.Option("--llm", help="Opt-in local Ollama classifier assist.")
    ] = False,
    llm_model: Annotated[str, typer.Option(help="Ollama model for --llm.")] = "llama3.2",
    output_format: Annotated[
        OutputFormat, typer.Option("--format", "-f", help="Output format.")
    ] = OutputFormat.CLI,
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Write output to a file.")
    ] = None,
    fail_on: Annotated[
        Severity | None,
        typer.Option(help="Exit non-zero if any finding is at/above this severity."),
    ] = Severity.HIGH,
) -> None:
    """Scan the installed MCP fleet for cross-server toxic flows."""
    if config:
        result = discover_fleet([_ExplicitConfigSource(path) for path in config])
    else:
        result = discover_fleet(default_sources(home=home, project=project))
    discovered = result.servers
    discovery_warnings = result.warnings

    if not discovered:
        err_console.print("[yellow]No MCP servers discovered.[/yellow]")

    backend = OllamaBackend(model=llm_model) if llm else None
    report = asyncio.run(
        scan_configs(
            discovered,
            introspect=introspect,
            timeout=timeout,
            llm_backend=backend,
            warnings=discovery_warnings,
        )
    )
    _emit(
        report.findings,
        report.warnings,
        output_format,
        output,
        servers=report.servers,
    )
    if fail_on is not None and _at_or_above(report.findings, fail_on):
        raise typer.Exit(code=1)


@app.command("lint-skills")
def lint_skills_command(
    paths: Annotated[list[Path], typer.Argument(help="Skill file(s) or directory tree(s).")],
    output_format: Annotated[
        OutputFormat, typer.Option("--format", "-f", help="Output format.")
    ] = OutputFormat.CLI,
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Write output to a file.")
    ] = None,
    fail_on: Annotated[
        Severity | None,
        typer.Option(help="Exit non-zero if any finding is at/above this severity."),
    ] = Severity.HIGH,
) -> None:
    """Lint SKILL.md files for dangerous declared capabilities."""
    findings, warnings = lint_skills(paths)
    _emit(findings, warnings, output_format, output)
    if fail_on is not None and _at_or_above(findings, fail_on):
        raise typer.Exit(code=1)


@app.command()
def rules() -> None:
    """List triflow's finding rules."""
    for rule in FINDING_RULES:
        console.print(f"[bold]{rule.rule_id}[/bold] ({rule.default_severity.value}) — {rule.name}")
        console.print(f"  {rule.summary}")


@app.command()
def version() -> None:
    """Print the triflow version."""
    console.print(__version__)


class _ExplicitConfigSource:
    """Parse a user-pointed config file that uses the ``mcpServers`` shape."""

    client = "config"

    def __init__(self, path: Path) -> None:
        self._path = path

    def discover(self) -> DiscoveryResult:
        data, warning = _load_json(self._path)
        result = DiscoveryResult(warnings=(warning,) if warning else ())
        if data is None:
            return result
        return result.merge(_parse_servers_map(data.get("mcpServers", {}), self.client, self._path))


if __name__ == "__main__":
    app()
