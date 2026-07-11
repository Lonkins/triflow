# ADR 0001: Metadata-only introspection — triflow never invokes a tool

## Status

Accepted

## Context

triflow needs to know what tools each configured MCP server exposes. The MCP
protocol offers `tools/list` (names, descriptions, JSON schemas) and
`tools/call` (execution). Calling tools would give richer signals (live
behavior, actual data returned) but would also make the scanner itself a
side-effecting agent: a scan could send email, delete files, or leak data —
exactly the class of harm triflow exists to prevent.

## Decision

Introspection sends only `initialize` and `tools/list` (plus protocol-required
notifications). `tools/call`, `resources/read`, `prompts/get`, and every other
side-effecting or data-reading request are forbidden. The guarantee is enforced
in three layers:

1. The introspection client exposes no API for calling tools.
2. A transport-level recorder in tests asserts the exact set of JSON-RPC
   methods sent during a scan.
3. Integration-test fixture servers write a sentinel file if any tool is ever
   executed; tests assert the sentinel does not exist.

Classification therefore relies on metadata heuristics (and an opt-in local
LLM), accepting lower fidelity in exchange for a scanner that is safe to run
against any fleet, including a compromised one.

## Consequences

- A malicious server can lie in its metadata; triflow's threat model documents
  this (metadata is treated as *untrusted input*, and lying servers are still
  caught by cross-server composition rules operating on what they *declare*).
- Scans are fast and side-effect free; safe to run in CI on every commit.
- Any future feature that needs tool execution must be rejected or built as a
  separate, clearly-labeled product. This ADR is the line.
