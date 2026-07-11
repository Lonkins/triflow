# triflow

[![CI](https://github.com/Lonkins/triflow/actions/workflows/ci.yml/badge.svg)](https://github.com/Lonkins/triflow/actions/workflows/ci.yml)
[![Docs](https://github.com/Lonkins/triflow/actions/workflows/docs.yml/badge.svg)](https://lonkins.github.io/triflow/)
[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-green.svg)](LICENSE)
[![Checked with mypy](https://img.shields.io/badge/mypy-strict-blue.svg)](https://mypy-lang.org/)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

**Cross-server MCP toxic-flow (lethal-trifecta) analyzer + `SKILL.md` linter.**

Single-server scanners inspect one MCP server at a time. triflow looks at the
**whole installed fleet** and asks: do these servers, *in combination*, compose
into an attack?

A filesystem server is fine. A web-fetch server is fine. An email server is
fine. Install all three under one agent and you have the **lethal trifecta** —
private-data access, untrusted-content ingress, and an exfiltration channel — so
a single poisoned web page can read your files and mail them out. No individual
server is misbehaving; the *composition* is the vulnerability.

```console
$ triflow scan -c examples/mcp.json --no-introspect
```

```text
 CRITICAL  TRIFLOW-TRIFECTA  Lethal trifecta present across servers
 Representative chain:
   config:filesystem [private_data_source]
   → config:fetch    [untrusted_content_ingress]
   → config:gmail    [exfiltration_channel]
 Fix: break one leg — scope the exfil tool, isolate the ingress server,
      or gate private-data reads behind approval.
```

## What it finds

| Finding | What it means |
|---------|---------------|
| **Lethal trifecta** | The fleet jointly has private-data + untrusted-ingress + exfiltration, naming the exact `server → tool` chain |
| **Tool shadowing** | The same tool name on two servers → a malicious server can impersonate a trusted one |
| **Injection-to-execution** | Untrusted ingress in one server reaching code execution in another → prompt injection becomes cross-server RCE |
| **Dangerous skills** | `SKILL.md` files with unbounded shell, network + secrets together, wildcard grants, or no scoping |

## Safety: it never invokes a tool

triflow introspects servers **metadata-only** — it sends `initialize` and
`tools/list` and nothing else. It will **never call a tool**. That guarantee is
enforced in code and asserted by transport-level and tripwire tests
([ADR-0001](docs/adr/0001-metadata-only-introspection.md)), so a scan is safe to
run in CI on every commit, even against a compromised fleet.

## Install

```bash
pip install triflow        # or: uv tool install triflow
```

> PyPI publishing is wired via Trusted Publishing (OIDC) and activates once the
> one-time PyPI-side publisher is configured — see
> [RELEASING.md](RELEASING.md). Until then, install from source with
> `uv sync --all-extras`.

## Use

```bash
# Scan the installed fleet (auto-discovers Claude Desktop/Code, Cursor, Windsurf)
triflow scan

# Scan a specific config, config-only (fast, side-effect free)
triflow scan -c .mcp.json --no-introspect

# Lint agent skills
triflow lint-skills .claude/skills

# Machine output for code scanning
triflow scan -c .mcp.json -f sarif -o triflow.sarif
```

`--fail-on high` (default) exits non-zero on high+ findings; `--no-fail` reports
without gating. Full CLI in the [usage docs](https://lonkins.github.io/triflow/usage/).

## GitHub Action

```yaml
- uses: Lonkins/triflow@v0.1.0
  with:
    config: .mcp.json
    skills: .claude/skills
    fail-on: high
  continue-on-error: true
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: ${{ steps.triflow.outputs.sarif-directory }}
```

Copy-paste workflow: [`examples/github-workflow.yml`](examples/github-workflow.yml).
Pre-commit hooks (`triflow-skills`, `triflow-scan`) ship in
[`.pre-commit-hooks.yaml`](.pre-commit-hooks.yaml).

## How capabilities are classified

Deterministic regex rules over tool names, descriptions, input-schema
properties, and server identity — every assignment carries **evidence** (which
rule matched what). An optional, opt-in local-LLM assist (Ollama, BYO) adds
semantic labels the regexes miss, strictly additively and clearly tagged. No
paid keys, ever. See the [capability taxonomy](https://lonkins.github.io/triflow/taxonomy/)
and [rule catalog](https://lonkins.github.io/triflow/rules/).

## Not a single-server scanner

triflow **complements** tools like [`mcp-scan`](https://github.com/invariantlabs-ai/mcp-scan)
and Snyk `agent-scan`. They inspect individual tool descriptions for injection
and rug-pulls; triflow reasons about composition across servers and lints skill
files. Run both — [why](https://lonkins.github.io/triflow/complements/).

## Development

```bash
uv sync --all-extras
uv run ruff check . && uv run mypy && uv run pytest --cov=triflow
```

Contributions welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). Security policy
in [SECURITY.md](SECURITY.md).

## License

[Apache-2.0](LICENSE)
