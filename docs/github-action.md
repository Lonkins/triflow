# GitHub Action

triflow ships a composite action that scans a repo's MCP config and lints its
skills, emitting SARIF for GitHub code scanning.

## Minimal usage

```yaml
name: triflow
on: [pull_request, push]

permissions:
  contents: read
  security-events: write

jobs:
  triflow:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - id: triflow
        uses: Lonkins/triflow@v0.1.0
        with:
          config: .mcp.json
          skills: .claude/skills
          fail-on: high
        continue-on-error: true
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ${{ steps.triflow.outputs.sarif-directory }}
```

A copy-paste version lives in
[`examples/github-workflow.yml`](https://github.com/Lonkins/triflow/blob/main/examples/github-workflow.yml).

## Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `config` | `""` | MCP config file to scan; empty auto-discovers |
| `skills` | `""` | Skill file or directory tree to lint |
| `introspect` | `false` | Launch servers for metadata-only tool listing |
| `fail-on` | `high` | Gate severity (`critical`/`high`/`medium`/`low`/`none`) |
| `version` | `""` | triflow version to install; empty installs from the action checkout |
| `results-dir` | `triflow-results` | Where SARIF files are written |

## Outputs

| Output | Description |
|--------|-------------|
| `sarif-directory` | Directory holding `triflow-fleet.sarif` and (if skills given) `triflow-skills.sarif` |

## Introspection in CI

The default `introspect: false` keeps the action fast and side-effect-free —
it classifies by server identity without launching anything. Set
`introspect: true` only when the runner can actually start your servers; even
then, triflow never invokes a tool.
