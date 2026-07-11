from pathlib import Path

from triflow.classify import (
    classify_fleet,
    classify_server_identity,
    classify_tool,
    load_rules,
)
from triflow.models import (
    Capability,
    IntrospectedServer,
    ServerConfig,
    ToolInfo,
    Transport,
)


def tool(name: str, description: str = "", schema: dict[str, object] | None = None) -> ToolInfo:
    return ToolInfo(name=name, description=description, input_schema=schema or {})


def caps(name: str, description: str = "", schema: dict[str, object] | None = None) -> set[str]:
    classified = classify_tool(tool(name, description, schema), "test:srv")
    return {str(c) for c in classified.capabilities}


def stdio_server(name: str, command: str, *args: str) -> ServerConfig:
    return ServerConfig(
        name=name,
        client="test",
        config_path=Path("cfg.json"),
        transport=Transport.STDIO,
        command=command,
        args=args,
    )


class TestCatalogIntegrity:
    def test_rule_ids_unique(self) -> None:
        ids = [r.spec.id for r in load_rules()]
        assert len(ids) == len(set(ids))

    def test_every_rule_has_patterns_and_rationale(self) -> None:
        for rule in load_rules():
            spec = rule.spec
            assert spec.rationale
            assert (
                spec.name_patterns
                or spec.description_patterns
                or spec.schema_property_patterns
                or spec.server_patterns
            ), f"rule {spec.id} matches nothing"

    def test_all_five_capabilities_covered(self) -> None:
        covered = {r.spec.capability for r in load_rules()}
        assert covered == set(Capability)


class TestToolClassification:
    def test_filesystem_tools(self) -> None:
        assert Capability.PRIVATE_DATA_SOURCE in caps("read_file")
        assert Capability.PRIVATE_DATA_SOURCE in caps("list_directory")
        assert Capability.STATE_CHANGING in caps("write_file")
        assert Capability.STATE_CHANGING in caps("delete_directory")

    def test_web_tools_are_ingress(self) -> None:
        assert Capability.UNTRUSTED_CONTENT_INGRESS in caps("fetch_url")
        assert Capability.UNTRUSTED_CONTENT_INGRESS in caps("web_search")
        assert Capability.UNTRUSTED_CONTENT_INGRESS in caps(
            "browse_page", "Navigate to a website and return its content"
        )

    def test_email_read_is_both_private_and_ingress(self) -> None:
        got = caps("search_inbox")
        assert Capability.PRIVATE_DATA_SOURCE in got
        assert Capability.UNTRUSTED_CONTENT_INGRESS in got

    def test_email_send_is_exfiltration(self) -> None:
        assert Capability.EXFILTRATION_CHANNEL in caps(
            "send_email", "Send an email to any recipient"
        )

    def test_chat_and_tracker_exfiltration(self) -> None:
        assert Capability.EXFILTRATION_CHANNEL in caps("post_message")
        assert Capability.EXFILTRATION_CHANNEL in caps("create_issue")

    def test_tracker_reads_are_ingress(self) -> None:
        assert Capability.UNTRUSTED_CONTENT_INGRESS in caps("get_issue_comments")

    def test_shell_and_code_execution(self) -> None:
        assert Capability.CODE_EXECUTION in caps("run_command")
        assert Capability.CODE_EXECUTION in caps(
            "sandbox", "Execute arbitrary Python code in a sandbox"
        )

    def test_database_query_is_private_data(self) -> None:
        assert Capability.PRIVATE_DATA_SOURCE in caps("execute_query")

    def test_description_matching_produces_evidence(self) -> None:
        classified = classify_tool(
            tool("summarize", "Reads the contents of a file and summarizes it"), "test:srv"
        )
        assert Capability.PRIVATE_DATA_SOURCE in classified.capabilities
        (ev,) = [e for e in classified.evidence if e.capability == Capability.PRIVATE_DATA_SOURCE]
        assert ev.matched_on == "tool_description"
        assert ev.rule_id == "PRIV-FS-READ"
        assert ev.excerpt

    def test_benign_tools_get_no_capabilities(self) -> None:
        assert caps("get_time") == set()
        assert caps("add_numbers", "Add two numbers together") == set()
        assert caps("format_markdown") == set()


class TestSchemaRules:
    def test_url_param_on_retrieval_tool_is_ingress(self) -> None:
        got = caps("load", schema={"properties": {"url": {"type": "string"}}})
        assert Capability.UNTRUSTED_CONTENT_INGRESS in got

    def test_url_param_requires_retrieval_name(self) -> None:
        # `send_email` has a url-ish schema? still not ingress via ING-URL-PARAM
        got = caps("send_email", schema={"properties": {"url": {"type": "string"}}})
        assert Capability.UNTRUSTED_CONTENT_INGRESS not in got

    def test_retrieval_name_without_url_param_does_not_fire_schema_rule(self) -> None:
        classified = classify_tool(tool("get_time"), "test:srv")
        assert classified.capabilities == frozenset()

    def test_schema_evidence_matched_on(self) -> None:
        classified = classify_tool(
            tool("load", schema={"properties": {"url": {"type": "string"}}}), "test:srv"
        )
        assert any(e.matched_on == "schema_property" for e in classified.evidence)


class TestServerIdentityFallback:
    def test_filesystem_server(self) -> None:
        config = stdio_server(
            "files", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/data"
        )
        capabilities, evidence = classify_server_identity(config)
        assert Capability.PRIVATE_DATA_SOURCE in capabilities
        assert Capability.STATE_CHANGING in capabilities
        assert all(e.matched_on == "server_identity" for e in evidence)

    def test_search_server(self) -> None:
        config = stdio_server(
            "brave-search", "npx", "-y", "@modelcontextprotocol/server-brave-search"
        )
        capabilities, _ = classify_server_identity(config)
        assert Capability.UNTRUSTED_CONTENT_INGRESS in capabilities

    def test_github_server_is_triple_threat(self) -> None:
        config = stdio_server("github", "docker", "run", "ghcr.io/github/github-mcp-server")
        capabilities, _ = classify_server_identity(config)
        assert {
            Capability.UNTRUSTED_CONTENT_INGRESS,
            Capability.PRIVATE_DATA_SOURCE,
            Capability.EXFILTRATION_CHANNEL,
        } <= capabilities

    def test_unknown_server_gets_nothing(self) -> None:
        config = stdio_server("acme-internal", "acme-mcp")
        capabilities, evidence = classify_server_identity(config)
        assert capabilities == frozenset() and evidence == ()


class TestFleetClassification:
    def test_classify_fleet_merges_tool_and_identity_signals(self) -> None:
        files = IntrospectedServer(
            config=stdio_server("files", "npx", "@modelcontextprotocol/server-filesystem"),
            tools=(tool("read_file"), tool("write_file")),
        )
        dead = IntrospectedServer(
            config=stdio_server("mystery", "mystery-mcp"),
            error="ConnectError: boom",
        )
        classified = classify_fleet([files, dead])
        by_name = {c.config.name: c for c in classified}
        assert Capability.PRIVATE_DATA_SOURCE in by_name["files"].all_capabilities
        assert Capability.STATE_CHANGING in by_name["files"].all_capabilities
        assert by_name["files"].tools[0].capabilities  # tool-level assignments present
        assert by_name["mystery"].introspection_error == "ConnectError: boom"
        assert by_name["mystery"].all_capabilities == frozenset()
