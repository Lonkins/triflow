from __future__ import annotations

from pathlib import Path

from triflow.models import FindingType, ServerConfig, Transport
from triflow.scan import scan_configs


def config_only_fleet() -> list[ServerConfig]:
    """Configs whose identities alone imply the trifecta (no introspection)."""
    return [
        ServerConfig(
            name="files",
            client="test",
            config_path=Path("cfg.json"),
            transport=Transport.STDIO,
            command="npx",
            args=("-y", "@modelcontextprotocol/server-filesystem", "/data"),
        ),
        ServerConfig(
            name="fetch",
            client="test",
            config_path=Path("cfg.json"),
            transport=Transport.STDIO,
            command="uvx",
            args=("mcp-server-fetch",),
        ),
        ServerConfig(
            name="gmail",
            client="test",
            config_path=Path("cfg.json"),
            transport=Transport.STDIO,
            command="npx",
            args=("gmail-mcp",),
        ),
    ]


class TestConfigOnlyScan:
    async def test_identity_only_scan_finds_trifecta_without_introspection(self) -> None:
        report = await scan_configs(config_only_fleet(), introspect=False)
        assert report.server_count == 3
        assert any(f.finding_type is FindingType.LETHAL_TRIFECTA for f in report.findings)
        # every server contributed via identity rules — no tools were listed
        assert all(server.tools == () for server in report.servers)

    async def test_warnings_passthrough(self) -> None:
        report = await scan_configs(
            config_only_fleet(), introspect=False, warnings=("discovery warned",)
        )
        assert "discovery warned" in report.warnings

    async def test_benign_config_only_scan_is_clean(self) -> None:
        benign = [
            ServerConfig(
                name="calc",
                client="test",
                config_path=Path("cfg.json"),
                transport=Transport.STDIO,
                command="acme-calc",
            )
        ]
        report = await scan_configs(benign, introspect=False)
        assert report.findings == ()
