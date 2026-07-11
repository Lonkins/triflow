# Releasing

triflow releases are automated by `.github/workflows/release.yml`, triggered by
a `v*` tag.

## Steps

1. Bump `version` in `pyproject.toml` and `__version__` in
   `src/triflow/__init__.py` (they must match — the release workflow enforces it).
2. Update `CHANGELOG.md`.
3. Merge to `main` via PR with green CI.
4. Tag and push:
   ```bash
   git tag v0.1.0
   git push origin v0.1.0
   ```
5. The workflow builds sdist + wheel, runs `twine check`, and verifies the tag
   matches the package version.

## PyPI publishing (one-time setup)

The `publish-pypi` job is dormant until:

1. A [Trusted Publisher][tp] is configured on PyPI for `Lonkins/triflow`
   (workflow `release.yml`, environment `pypi`). This needs a PyPI account and
   is the one manual, credential-bearing step.
2. The repository variable `PYPI_ENABLED` is set to `true`.

No API token is ever stored — publishing uses OIDC. Until this setup is done,
releases still build and validate artifacts; only the upload step is skipped.

[tp]: https://docs.pypi.org/trusted-publishers/
