# Contributing to triflow

Thanks for helping make agent fleets safer.

## Setup

```bash
git clone https://github.com/Lonkins/triflow
cd triflow
uv sync --all-extras
pre-commit install
```

## Workflow

- `main` is protected; all changes land via pull request with green CI.
- Branch from `main`, keep PRs focused, squash-merge.
- Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`, `chore:`, `refactor:`).
- Every behavior change needs tests. Rule changes need fixture coverage.

## Checks (CI runs the same)

```bash
uv run ruff format --check .
uv run ruff check .
uv run mypy
uv run pytest --cov=triflow
```

## Hard rules

- **Never** add a code path that invokes an MCP tool. Introspection is
  metadata-only (`initialize` + `tools/list` and nothing else); tests enforce this.
- No new runtime dependencies without discussion in an issue first.
- New detection rules must ship with: rule ID, rationale, at least one
  triggering fixture and one non-triggering fixture, and a docs entry in the
  rule catalog.
- Architectural decisions get an ADR under `docs/adr/`.

## Reporting security issues

See [SECURITY.md](SECURITY.md) — do not open public issues for vulnerabilities.
