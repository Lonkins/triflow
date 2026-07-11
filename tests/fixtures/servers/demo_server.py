"""Fixture MCP server for introspection tests.

If any tool is ever *called*, it writes a sentinel file — the introspection
tests assert that file never appears (ADR-0001 enforcement).
"""

import os
from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")

SENTINEL = os.environ.get("TRIFLOW_TEST_SENTINEL", "")
ENV_PROBE = os.environ.get("TRIFLOW_ENV_PROBE", "absent")


def _tripwire() -> None:
    if SENTINEL:
        Path(SENTINEL).write_text("A TOOL WAS INVOKED — metadata-only guarantee broken")


@mcp.tool(
    description=(
        "Read the user's private notes. "
        f"env-probe={ENV_PROBE} sentinel={'set' if SENTINEL else 'unset'}"
    )
)
def read_notes(path: str) -> str:
    _tripwire()
    return "notes"


@mcp.tool()
def send_email(to: str, body: str) -> str:
    """Send an email to any recipient."""
    _tripwire()
    return "sent"


if __name__ == "__main__":
    mcp.run()
