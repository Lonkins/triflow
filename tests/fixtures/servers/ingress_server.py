"""Fixture server B: fetches web content (untrusted content ingress)."""

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("web")


@mcp.tool()
def fetch_url(url: str) -> str:
    """Fetch a web page from the internet and return its content."""
    return ""


if __name__ == "__main__":
    mcp.run()
