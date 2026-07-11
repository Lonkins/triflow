import json
import shutil
from pathlib import Path

from triflow.discovery import (
    ClaudeCodeSource,
    ClaudeDesktopSource,
    ConfigSource,
    CursorSource,
    WindsurfSource,
    default_sources,
    discover_fleet,
)
from triflow.models import Transport

FIXTURES = Path(__file__).parent / "fixtures" / "configs"


def install_fixture(fixture: str, dest: Path) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy(FIXTURES / fixture, dest)
    return dest


def macos_desktop_config(home: Path) -> Path:
    return home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"


class TestClaudeDesktop:
    def test_platform_paths(self, tmp_path: Path) -> None:
        by_platform = {
            "darwin": macos_desktop_config(tmp_path),
            "win32": tmp_path / "AppData" / "Roaming" / "Claude" / "claude_desktop_config.json",
            "linux": tmp_path / ".config" / "Claude" / "claude_desktop_config.json",
        }
        for platform, expected in by_platform.items():
            source = ClaudeDesktopSource(home=tmp_path, platform=platform)
            assert source.config_path() == expected

    def test_parses_stdio_and_http(self, tmp_path: Path) -> None:
        install_fixture("claude_desktop_config.json", macos_desktop_config(tmp_path))
        result = ClaudeDesktopSource(home=tmp_path, platform="darwin").discover()
        assert result.warnings == ()
        by_name = {s.name: s for s in result.servers}
        files = by_name["files"]
        assert files.transport is Transport.STDIO
        assert files.command == "npx"
        assert files.args[0] == "-y"
        assert files.env == {"FS_ROOT": "/Users/example/Documents"}
        linear = by_name["linear"]
        assert linear.transport is Transport.HTTP
        assert linear.url is not None and linear.url.startswith("https://mcp.linear.example")
        assert linear.slug == "claude-desktop:linear"

    def test_secrets_never_serialized(self, tmp_path: Path) -> None:
        install_fixture("claude_desktop_config.json", macos_desktop_config(tmp_path))
        result = ClaudeDesktopSource(home=tmp_path, platform="darwin").discover()
        for server in result.servers:
            dumped = server.model_dump_json() + repr(server) + str(server.model_dump())
            assert "FIXTURE-PLACEHOLDER" not in dumped
            assert "FS_ROOT" not in dumped

    def test_missing_file_is_silent(self, tmp_path: Path) -> None:
        result = ClaudeDesktopSource(home=tmp_path, platform="darwin").discover()
        assert result.servers == () and result.warnings == ()


class TestClaudeCode:
    def test_global_project_and_nested_projects(self, tmp_path: Path) -> None:
        home, project = tmp_path / "home", tmp_path / "proj"
        install_fixture("dot_claude.json", home / ".claude.json")
        project.mkdir()
        (project / ".mcp.json").write_text(
            json.dumps({"mcpServers": {"local-db": {"command": "uvx", "args": ["mcp-sqlite"]}}})
        )
        result = ClaudeCodeSource(home=home, project=project).discover()
        names = {s.name for s in result.servers}
        assert names == {"web-search", "mailer", "local-db"}
        assert all(s.client == "claude-code" for s in result.servers)

    def test_home_only(self, tmp_path: Path) -> None:
        install_fixture("dot_claude.json", tmp_path / "home" / ".claude.json")
        result = ClaudeCodeSource(home=tmp_path / "home", project=tmp_path / "nope").discover()
        assert {s.name for s in result.servers} == {"web-search", "mailer"}


class TestCursorAndWindsurf:
    def test_cursor_home_and_project(self, tmp_path: Path) -> None:
        home, project = tmp_path / "home", tmp_path / "proj"
        install_fixture("cursor_mcp.json", home / ".cursor" / "mcp.json")
        (project / ".cursor").mkdir(parents=True)
        (project / ".cursor" / "mcp.json").write_text(
            json.dumps({"mcpServers": {"scratch": {"command": "python3", "args": ["srv.py"]}}})
        )
        result = CursorSource(home=home, project=project).discover()
        assert {s.name for s in result.servers} == {"github", "scratch"}

    def test_windsurf_serverurl_and_sse(self, tmp_path: Path) -> None:
        install_fixture(
            "windsurf_mcp_config.json", tmp_path / ".codeium" / "windsurf" / "mcp_config.json"
        )
        result = WindsurfSource(home=tmp_path).discover()
        (slack,) = result.servers
        assert slack.transport is Transport.SSE
        assert slack.url == "https://mcp.slack.example/mcp"


class TestRobustness:
    def test_malformed_json_warns(self, tmp_path: Path) -> None:
        path = macos_desktop_config(tmp_path)
        path.parent.mkdir(parents=True)
        path.write_text("{not json")
        result = ClaudeDesktopSource(home=tmp_path, platform="darwin").discover()
        assert result.servers == ()
        assert len(result.warnings) == 1 and "unreadable" in result.warnings[0]

    def test_top_level_not_object_warns(self, tmp_path: Path) -> None:
        path = macos_desktop_config(tmp_path)
        path.parent.mkdir(parents=True)
        path.write_text("[1, 2]")
        result = ClaudeDesktopSource(home=tmp_path, platform="darwin").discover()
        assert "expected a JSON object" in result.warnings[0]

    def test_bad_shapes_warn_but_do_not_crash(self, tmp_path: Path) -> None:
        install_fixture("bad_shapes.json", macos_desktop_config(tmp_path))
        result = ClaudeDesktopSource(home=tmp_path, platform="darwin").discover()
        assert result.servers == ()
        assert len(result.warnings) == 3

    def test_mcp_servers_not_object_warns(self, tmp_path: Path) -> None:
        path = macos_desktop_config(tmp_path)
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps({"mcpServers": ["a"]}))
        result = ClaudeDesktopSource(home=tmp_path, platform="darwin").discover()
        assert "mcpServers is not an object" in result.warnings[0]


class TestFleet:
    def test_default_sources_cover_four_clients(self, tmp_path: Path) -> None:
        sources = default_sources(home=tmp_path, project=tmp_path)
        assert {s.client for s in sources} == {
            "claude-desktop",
            "claude-code",
            "cursor",
            "windsurf",
        }
        assert all(isinstance(s, ConfigSource) for s in sources)

    def test_discover_fleet_merges_servers_and_warnings(self, tmp_path: Path) -> None:
        home, project = tmp_path / "home", tmp_path / "proj"
        project.mkdir(parents=True)
        install_fixture("claude_desktop_config.json", macos_desktop_config(home))
        install_fixture("cursor_mcp.json", home / ".cursor" / "mcp.json")
        bad = home / ".codeium" / "windsurf" / "mcp_config.json"
        bad.parent.mkdir(parents=True)
        bad.write_text("nope{")
        sources: list[ConfigSource] = [
            ClaudeDesktopSource(home=home, platform="darwin"),
            CursorSource(home=home, project=project),
            WindsurfSource(home=home),
        ]
        result = discover_fleet(sources)
        assert {s.slug for s in result.servers} == {
            "claude-desktop:files",
            "claude-desktop:linear",
            "cursor:github",
        }
        assert len(result.warnings) == 1
