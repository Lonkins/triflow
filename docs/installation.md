# Installation

## From PyPI

```bash
pip install triflow
# or
uv tool install triflow
```

This installs the `triflow` CLI.

!!! note "PyPI availability"
    triflow publishes to PyPI via [Trusted Publishing][tp] (OIDC — no stored
    token). The release workflow is dormant until the one-time PyPI-side
    Trusted Publisher is configured for `Lonkins/triflow` and the
    `PYPI_ENABLED` repository variable is set to `true`. Until then, install
    from source.

## From source

```bash
git clone https://github.com/Lonkins/triflow
cd triflow
uv sync --all-extras
uv run triflow --help
```

## Requirements

- Python 3.12+
- No paid keys, no cloud services. The optional local-LLM assist expects a
  local [Ollama][ollama] instance and is off by default.

[tp]: https://docs.pypi.org/trusted-publishers/
[ollama]: https://ollama.com/
