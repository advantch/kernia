# Contributing to Kernia

Thanks for your interest in Kernia. This guide gets you from clone to green
tests, and explains the project's conventions.

## Project shape

Kernia is a `uv` workspace. Every shippable unit is its own package under
`packages/`:

- `packages/core` — the `kernia` package: framework-agnostic core + all
  built-in plugins.
- `packages/<adapter>` — `memory_adapter`, `sqlalchemy_adapter`, `mongo_adapter`,
  `redis_storage`.
- `packages/<plugin>` — standalone plugins shipped as their own dist:
  `api_key`, `passkey`, `sso`, `oauth_provider`, `scim`, `stripe`, `mcp`.
- `packages/<integration>` — `fastapi_integration`, `starlette_integration`,
  `django_integration`.
- `packages/cli`, `packages/test_utils`.

Tests live in two places:

- `packages/<pkg>/tests/` — pure unit tests for that package.
- `e2e/` — `adapter/` (cross-adapter conformance), `plugins/` (one file per
  plugin, driven through the ASGI router), `integration/` (cross-cutting flows).

## Setup

```bash
git clone https://github.com/advantch/kernia
cd kernia
uv sync
uv pip install -e packages/core -e packages/memory_adapter -e packages/sqlalchemy_adapter
```

## Running the suite

```bash
# fast inner loop — e2e against memory + sqlite
uv run pytest e2e/ -q

# a single plugin
uv run pytest e2e/plugins/test_organization.py -q

# everything (Docker required for postgres/mysql/mongo/redis)
uv run pytest -q
```

Docker-gated suites skip cleanly when Docker isn't running.

## Quality gates (CI runs all of these)

```bash
uv run ruff check .          # lint
uv run ruff format --check . # format
uv run mypy packages/core/src
```

## Wire compatibility

Kernia is wire-compatible with Better Auth: the official Better Auth JS client
must work against a Kernia server unchanged. When you add or change a plugin:

1. Keep the route paths and the camelCase wire shape stable — the
   `examples/frontend/scripts/wire-check.mjs` harness drives the official JS
   client end to end to verify this.
2. Add unit tests for pure logic (token formats, schema, claim verification).
3. Add an integration test under `e2e/plugins/test_<name>.py` that drives every
   endpoint via `ASGIDriver`, parametrized over adapters where it matters.
4. Register the plugin's error codes via `KerniaPlugin.error_codes`.

## Commit + PR conventions

- Conventional Commits: `feat(scope):`, `fix(scope):`, `docs:`, `test(scope):`,
  `chore:`. Use `!` for breaking changes.
- Bug fixes and features **must** include tests. For a reproducible bug, write
  the failing test first.
- Reference the upstream issue/PR with a `@see` comment when porting a regression
  fix, so the provenance is auditable.
- Keep PRs scoped to one plugin/area where possible.

## Docs

User-facing changes update the Fumadocs site under `apps/docs/content/docs/`.
Follow the existing MDX structure (frontmatter `title` + `description`, fenced
code blocks with `title=`, `APIMethod` blocks for routes). Add new pages to the
relevant `meta.json`.

## License

By contributing you agree your contributions are licensed under the
[MIT License](./LICENSE).
