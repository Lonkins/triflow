# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/) and this project adheres to
[Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-07-11

Initial release.

### Added

- **Discovery**: pluggable `ConfigSource` protocol with implementations for
  Claude Desktop, Claude Code, Cursor, and Windsurf.
- **Introspection**: metadata-only tool listing over stdio, streamable HTTP,
  and SSE — sends `initialize` + `tools/list` only, never invokes a tool.
  Minimized subprocess environment and hard per-server timeouts.
- **Capability taxonomy** and a deterministic, evidence-producing classifier
  driven by a packaged rule catalog; optional opt-in local-LLM (Ollama) assist.
- **Cross-server toxic-flow engine**: lethal-trifecta detection, tool
  shadowing, and injection-to-execution escalation chains — each finding names
  the exact server → tool chain.
- **`SKILL.md` linter**: unbounded shell, network + secret access, missing
  `allowed-tools` scoping, and over-broad wildcard grants.
- **Reporters**: rich CLI, JSON, and SARIF 2.1.0.
- **CLI**: `scan`, `lint-skills`, `rules`, `version`.
- **GitHub Action** and **pre-commit hooks** with a runnable example workflow.
- **Docs** (MkDocs Material): taxonomy, rule catalog, threat model, and a
  "complements single-server scanners" page.

[0.1.0]: https://github.com/Lonkins/triflow/releases/tag/v0.1.0
