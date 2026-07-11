"""Fixture server A: reads local files (private data source).

The tool body is inert — triflow never calls it, and these tests assert that.
"""

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("files")


@mcp.tool()
def read_file(path: str) -> str:
    """Read the contents of a local file."""
    return ""


if __name__ == "__main__":
    mcp.run()
