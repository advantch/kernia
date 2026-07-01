# Releasing

Kernia ships as 17 packages published to PyPI in **lockstep**: they always share
one version, matched by a single git tag `v<version>`. Pushing that tag runs the
[`Release`](.github/workflows/publish.yml) workflow, which builds every package
with `uv build`, validates metadata, and uploads with `uv publish`.

## One-time setup (no tokens)

Publishing authenticates via **PyPI Trusted Publishing** (OIDC): PyPI trusts
this repo's `publish.yml` workflow directly, so there is no API token to create,
store, or rotate.

1. On PyPI (<https://pypi.org/manage/account/publishing/>), each `kernia*`
   project has a trusted publisher registered: owner `advantch`, repository
   `kernia`, workflow `publish.yml`, environment `pypi`. Before the first
   release these are "pending publishers" (they claim the project name); after
   the first upload they become regular per-project publishers.
2. The repo has a `pypi` [environment](https://github.com/advantch/kernia/settings/environments).
   Add required reviewers to it if you want a manual approval gate before every
   upload.

## Cutting a release

```bash
# 1. Bump every package to the new version (and re-pin the kernia dependency)
uv run --with tomlkit python scripts/bump_version.py 0.2.0

# 2. Sanity-check locally
uv build --package kernia --out-dir dist/ && uvx twine check dist/*

# 3. Commit, tag, push
git commit -am "release: v0.2.0"
git tag v0.2.0
git push --follow-tags
```

The tag must match `packages/core/pyproject.toml` — the workflow fails the build
if `v<tag>` and the core version disagree, so a mistagged release never uploads.

Use pre-release versions for testing: `0.2.0rc1` publishes to PyPI as a
pre-release that `pip install kernia` skips by default.

## Dry run (no upload)

Run the **Release** workflow manually from the Actions tab with `dry_run` left on
(the default). It builds all packages and runs `twine check` without touching
PyPI, so you can verify the artifacts before tagging.

## Versioning policy

- All packages move together; there are no independent per-package versions.
- Follow semver. Pre-1.0, breaking changes bump the minor.
- Every published package pins `kernia>=<version>` so a plugin never resolves
  against an older, incompatible core.
