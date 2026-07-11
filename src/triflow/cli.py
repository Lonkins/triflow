"""Typer CLI entry point. Subcommands land with the reporter build part."""

from __future__ import annotations

import typer

from triflow import __version__

app = typer.Typer(
    name="triflow",
    help="Cross-server MCP toxic-flow analyzer and SKILL.md linter.",
    no_args_is_help=True,
)


@app.callback()
def main() -> None:
    """Cross-server MCP toxic-flow analyzer and SKILL.md linter."""


@app.command()
def version() -> None:
    """Print the triflow version."""
    typer.echo(__version__)


if __name__ == "__main__":
    app()
