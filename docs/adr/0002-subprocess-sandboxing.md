# ADR 0002: Stdio server launch — minimized environment + hard timeouts

## Status

Accepted

## Context

Introspecting a stdio MCP server means executing whatever command its config
declares. That command is untrusted from triflow's point of view: it might be
malicious, broken, or simply hang. Full OS-level sandboxing (seccomp, sandbox
profiles, containers) is platform-specific and heavyweight for a scanner that
must run anywhere, including inside CI.

## Decision

Best-effort containment with three portable guards:

1. **Minimized environment.** Servers get the MCP SDK's safe inherited set
   (`PATH`, `HOME`, ... — no arbitrary parent vars) plus only the env vars
   their own config block declares. The scanner's environment — CI tokens,
   cloud credentials — never reaches an introspected server.
2. **Hard wall-clock timeout** (default 15 s) around connect + handshake +
   `tools/list`, enforced with an anyio cancel scope. On expiry the SDK
   terminates the subprocess tree.
3. **No shell.** `command`/`args` are exec'd directly; no interpolation.

Fleet introspection is sequential by design: no subprocess storm, and
per-server timeouts bound total scan time at `n × timeout` worst case.

We explicitly do **not** claim OS-level isolation. A hostile server binary can
do anything the scanning user can do — the mitigation is that triflow works
fine *without* introspection (config-only scanning) and introspection is
opt-in per invocation.

## Consequences

- Servers that require undeclared environment variables will fail to start
  under introspection; their failure is reported as data, not a crash.
- Users scanning fully untrusted configs should prefer config-only mode or
  run triflow inside a container.
