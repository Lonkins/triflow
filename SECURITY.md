# Security Policy

## Supported Versions

Only the latest release of triflow receives security fixes.

## Reporting a Vulnerability

Please report vulnerabilities privately via
[GitHub Security Advisories](https://github.com/Lonkins/triflow/security/advisories/new).
Do not open a public issue for an exploitable bug.

You can expect an acknowledgement within 7 days. Coordinated disclosure preferred;
we will credit reporters in the release notes unless you ask otherwise.

## Scope notes

- triflow introspects MCP servers **metadata-only** — it must never invoke a tool.
  Any code path that causes a `tools/call` (or any other side-effecting MCP
  request) to be sent during a scan is a security vulnerability, not just a bug.
- triflow parses attacker-influenced input: MCP client config files, tool
  metadata returned by servers, and `SKILL.md` files. Parser behavior that leads
  to code execution, path traversal, or resource exhaustion is in scope.
- Introspected server subprocesses are launched with a minimized environment and
  hard timeouts. Bypasses of those guards (e.g. secret-bearing environment
  variables leaking into a server that should not receive them) are in scope.
- YAML loading uses `yaml.safe_load` only. Any bypass of that is in scope.
