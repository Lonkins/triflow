"""Rich console reporter."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from triflow.models import ClassifiedServer, Finding, Severity

_SEVERITY_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "dim",
}


def _summary_line(findings: tuple[Finding, ...]) -> Text:
    if not findings:
        return Text("No findings.", style="bold green")
    counts = {s: sum(1 for f in findings if f.severity == s) for s in Severity}
    text = Text()
    for severity in Severity:
        if counts[severity]:
            text.append(f" {counts[severity]} {severity.value} ", style=_SEVERITY_STYLE[severity])
            text.append(" ")
    return text


def render_console(
    findings: tuple[Finding, ...],
    warnings: tuple[str, ...] = (),
    *,
    servers: tuple[ClassifiedServer, ...] | None = None,
    console: Console | None = None,
) -> None:
    console = console or Console()

    if servers is not None:
        fleet = Table(title="Installed MCP fleet", title_justify="left", expand=False)
        fleet.add_column("Server", style="cyan")
        fleet.add_column("Transport")
        fleet.add_column("Capabilities")
        fleet.add_column("Tools", justify="right")
        for server in servers:
            caps = ", ".join(sorted(c.value for c in server.all_capabilities)) or "—"
            note = " (introspection failed)" if server.introspection_error else ""
            fleet.add_row(
                server.slug + note,
                server.config.transport.value,
                caps,
                str(len(server.tools)),
            )
        console.print(fleet)
        console.print()

    console.print(Panel(_summary_line(findings), title="triflow", expand=False))

    for finding in findings:
        style = _SEVERITY_STYLE[finding.severity]
        header = Text()
        header.append(f" {finding.severity.value.upper()} ", style=style)
        header.append(f" {finding.rule_id}  ", style="bold")
        header.append(finding.title)
        body = Text()
        body.append(finding.detail + "\n\n", style="default")
        if finding.participants:
            body.append("Chain: ", style="bold")
            body.append(" → ".join(p.ref for p in finding.participants) + "\n")
        if finding.location is not None:
            body.append("File: ", style="bold")
            body.append(finding.location.path + "\n")
        body.append("Fix: ", style="bold green")
        body.append(finding.remediation)
        console.print(Panel(body, title=header, title_align="left", border_style=style))

    if warnings:
        warn = Text()
        for message in warnings:
            warn.append(f"• {message}\n", style="yellow")
        console.print(Panel(warn, title="Warnings", border_style="yellow", expand=False))
