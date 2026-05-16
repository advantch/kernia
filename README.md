# better-auth-python

A Python port of [better-auth](https://github.com/better-auth/better-auth), structured to mirror the reference TypeScript codebase one-to-one. No shortcuts: every layer (plugin contract, adapter contract, endpoint factory, cookie/session model, error registry) is defined as a strict Protocol before any feature code is written.

## Status

MVP complete. 49/49 tests passing.

| Layer | Status |
|---|---|
| Workspace layout (mirrors `reference/packages/better-auth/src/`) | ✅ |
| Plugin Protocol (`BetterAuthPlugin`) | ✅ |
| Adapter Protocol (`CustomAdapter` + `ConsumingAdapter` + `SchemaAdapter`) | ✅ |
| Endpoint factory (`create_auth_endpoint`) | ✅ |
| Cookie signing + parsing (wire-compatible with better-auth JS) | ✅ |
| Error registry | ✅ |
| Core schema (user, session, account, verification) | ✅ |
| In-memory adapter (test oracle) | ✅ |
| SQLAlchemy 2.x async adapter (Postgres / SQLite / MySQL) | ✅ |
| Adapter conformance suite (15 tests × 2 adapters = 30 green) | ✅ |
| ASGI `Router.mount()` — full lifecycle | ✅ |
| Email/password handlers (sign-up, sign-in, sign-out, get-session, reset) | ✅ |
| scrypt password hashing (stdlib only) | ✅ |
| OAuth2 primitives: PKCE + RS256 id_token verify (stdlib only) | ✅ |
| Google social provider | ✅ |
| FastAPI integration (`mount_better_auth`, `get_session`, `require_session`) | ✅ |
| Layout audit (CI gate, enforces 1:1 mirror with reference) | ✅ |
| Full wire-protocol e2e (signup→signin→get-session→sign-out, both adapters) | ✅ |
| Spec docs (wire-protocol, plugin, adapter, endpoint, cookie, file-mapping, conformance) | ✅ |

## Repository layout

```
.
├── reference/                              # better-auth v1.6.11 (git submodule)
├── spec/                                   # extracted contract docs (source of truth)
├── packages/
│   ├── core/                               # better-auth Python core
│   │   └── src/better_auth/
│   │       ├── api/                        # endpoint factory + router
│   │       ├── auth/                       # init() entry point
│   │       ├── cookies/                    # signing + Set-Cookie rendering
│   │       ├── db/{adapter,schema}/        # adapter factory + canonical models
│   │       ├── error/                      # APIError + ErrorRegistry
│   │       ├── oauth2/                     # PKCE, code exchange, JWT verify
│   │       ├── plugins/email_password/     # built-in plugin
│   │       ├── social_providers/           # OAuthProvider + google
│   │       └── types/                      # all Protocol definitions
│   ├── memory_adapter/                     # in-memory adapter (test oracle)
│   ├── sqlalchemy_adapter/                 # SQLAlchemy 2.x async adapter
│   ├── fastapi_integration/                # FastAPI mount + dependencies
│   ├── cli/                                # codegen, migrations
│   ├── test_utils/                         # shared test fixtures
│   └── _stubs/                             # layout-locked stubs for: passkey,
│                                           #   sso, oauth_provider, drizzle/prisma/
│                                           #   kysely/mongo adapter, redis_storage,
│                                           #   telemetry, api_key, scim, stripe, …
├── e2e/
│   ├── adapter/test_adapter_contract.py    # conformance suite
│   └── smoke/test_init.py
├── scripts/audit_layout.py                 # enforces 1:1 directory mapping
└── pyproject.toml                          # uv workspace
```

## Quickstart

```bash
git clone --recurse-submodules <this-repo>
cd better-auth-python
uv sync
uv pip install -e packages/core -e packages/memory_adapter
uv pip install pytest pytest-asyncio anyio

# Architectural rigor gate — fails if better-auth grows a directory we don't mirror.
uv run python scripts/audit_layout.py

# Adapter conformance + smoke
uv run pytest e2e/ -v
```

## Architecture

The defining decision: this port reproduces the file/folder layout of
`reference/packages/better-auth/src/` directory-for-directory. New better-auth
directories upstream must either get a Python counterpart, a stub under
`packages/_stubs/`, or an explicit waiver in `scripts/audit_layout.py`. CI fails
otherwise.

- **Plugin contract** — `BetterAuthPlugin` is a `typing.Protocol`. Field-for-field
  the same as the TypeScript interface (`id`, `schema`, `endpoints`, `hooks`,
  `middlewares`, `on_request`, `on_response`, `rate_limit`, `error_codes`, `init`).
  See `packages/core/src/better_auth/types/plugin.py`.
- **Adapter contract** — `CustomAdapter` is a `typing.Protocol`. Every method
  matches the reference signatures. See
  `packages/core/src/better_auth/types/adapter.py`. The conformance suite at
  `e2e/adapter/test_adapter_contract.py` runs against every registered adapter; a
  new adapter is one line in the `ADAPTERS` list.
- **Wire protocol** — endpoint paths, payload shapes, and cookie names match
  better-auth exactly so the existing JS client (`better-auth/client`) can talk to
  a Python server unchanged. Documented in `spec/wire-protocol.md`.
- **Async-only** — every Protocol method returns an `Awaitable`. Sync users wrap
  with `anyio.from_thread` at the edge.

## Reference pin

`reference/` is pinned to better-auth `v1.6.11`. Bumping the submodule is an
explicit step that requires re-running `scripts/audit_layout.py` and updating the
specs under `spec/`.
