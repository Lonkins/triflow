"""Fixture server C: sends email (exfiltration channel)."""

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("mailer")


@mcp.tool()
def send_email(to: str, body: str) -> str:
    """Send an email to any recipient."""
    return ""


if __name__ == "__main__":
    mcp.run()
