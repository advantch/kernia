# Releasing

Kernia ships as three distributions published to PyPI in **lockstep**: they
always share one version, matched by a single git tag `v<version>`.

- **`kernia`** — the library. Optional adapters, server integrations, and
  plugins are extras of this one wheel (`pip install "kernia[fastapi,sqlalchemy]"`).
- **`kernia-cli`** — the command-line tool.
- **`kernia-test-utils`** — the ASGI test driver and helpers.

Pushing a `v<version>` tag runs the
[`Release`](.github/workflows/publish.yml) workflow, which builds all three with
`uv build`, validates metadata, and uploads with `uv publish`.

## One-time setup (no tokens)

Publishing authenticates via **PyPI Trusted Publishing** (OIDC): PyPI trusts
this repo's `publish.yml` workflow directly, so there is no API token to create,
store, or rotate.

1. On PyPI (<https://pypi.org/manage/account/publishing/>), each of the three
   projects has a trusted publisher registered: owner `advantch`, repository
   `kernia`, workflow `publish.yml`, and its own environment — `pypi` for
   `kernia`, `pypi-cli` for `kernia-cli`, `pypi-test-utils` for
   `kernia-test-utils`. (PyPI keys a trusted publisher on the tuple of owner,
   repo, workflow, and environment, so each project needs a distinct
   environment.) Before the first release these are "pending publishers" (they
   claim the project name); after the first upload they become regular
   per-project publishers.
2. The repo has matching `pypi`, `pypi-cli`, and `pypi-test-utils`
   [environments](https://github.com/advantch/kernia/settings/environments).
   Add required reviewers to any of them for a manual approval gate before
   upload.

## Cutting a release

```bash
# 1. Bump all three packages to the new version (and re-pin the kernia dependency)
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

- All three distributions move together; there are no independent per-package
  versions.
- Follow semver. Pre-1.0, breaking changes bump the minor.
- `kernia-cli` and `kernia-test-utils` pin `kernia>=<version>` so they never
  resolve against an older, incompatible core.
