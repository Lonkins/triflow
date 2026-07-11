# Usage

## Scan the installed fleet

```bash
# Auto-discover configs (Claude Desktop, Claude Code, Cursor, Windsurf)
triflow scan

# Scan a specific config file, config-only (fast, no subprocesses)
triflow scan -c .mcp.json --no-introspect

# Introspect servers for real tool metadata (metadata-only; never invokes tools)
triflow scan -c .mcp.json --introspect
```

### Introspection vs config-only

| Mode | What it uses | When |
|------|--------------|------|
| `--introspect` (default) | Live `tools/list` metadata | Highest fidelity; launches each stdio server briefly |
| `--no-introspect` | Server identity heuristics only | Fast, side-effect-free, CI-friendly |

Even with `--introspect`, triflow **never calls a tool** — only `initialize`
and `tools/list` are ever sent.

## Lint skills

```bash
triflow lint-skills path/to/SKILL.md
triflow lint-skills .claude/skills          # walks the tree for SKILL.md files
```

## Output formats

```bash
triflow scan -c .mcp.json -f cli            # rich terminal (default)
triflow scan -c .mcp.json -f json           # machine-readable
triflow scan -c .mcp.json -f sarif -o out.sarif   # code scanning
```

## Exit codes and gating

| Flag | Behavior |
|------|----------|
| `--fail-on high` (default) | Exit 1 if any finding is high or above |
| `--fail-on critical` | Exit 1 only on critical findings |
| `--no-fail` | Always exit 0 (still reports) |

Exit `0` = clean/under threshold, `1` = findings at/above the gate, `2` = usage
error.

## Optional local-LLM assist

```bash
# Requires a local Ollama instance; strictly additive to the deterministic rules
triflow scan -c .mcp.json --llm --llm-model llama3.2
```

Findings the model contributes are tagged `LLM-ASSIST` in evidence. See
[ADR-0003](adr/0003-local-llm-opt-in.md).

## Pre-commit hooks

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/Lonkins/triflow
    rev: v0.1.0
    hooks:
      - id: triflow-skills   # lints changed SKILL.md files
      - id: triflow-scan     # config-only fleet scan when an mcp config changes
```

## List the rules

```bash
triflow rules
```
