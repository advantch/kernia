<div align="center">

# Kernia

**Comprehensive authentication for Python — the Better Auth model, natively for ASGI.**

Email/password, OAuth, magic links, passkeys, organizations, SSO, SCIM, Stripe billing,
and 30+ plugins. Wire-compatible with the official [Better Auth](https://better-auth.com)
JavaScript client, so your existing frontend just works.

[![CI](https://github.com/advantch/kernia/actions/workflows/ci.yml/badge.svg)](https://github.com/advantch/kernia/actions/workflows/ci.yml)
[![Security](https://github.com/advantch/kernia/actions/workflows/security.yml/badge.svg)](https://github.com/advantch/kernia/actions/workflows/security.yml)
[![PyPI](https://img.shields.io/pypi/v/kernia.svg)](https://pypi.org/project/kernia/)
[![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12-blue.svg)](https://pypi.org/project/kernia/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](./LICENSE)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![Docs](https://img.shields.io/badge/docs-kernia-black.svg)](https://docs-advantch.vercel.app)

[Live demo](https://kernia-demo-delta.vercel.app) ·
[Documentation](https://docs-advantch.vercel.app) ·
[Quickstart](#quickstart) ·
[Plugins](#whats-included) ·
[Examples](./examples) ·
[Contributing](./CONTRIBUTING.md)

</div>

---

Kernia is an independent Python implementation compatible with **Better Auth 1.6.11**.
It preserves the Better Auth wire protocol — same routes, same cookie model, same
camelCase payloads — while exposing a Python-native `kernia` package family for
FastAPI, Starlette, and Django. No upstream source is vendored.

```python
from kernia import KerniaOptions
from kernia.auth import init
from kernia.plugins import email_and_password
from kernia.plugins.organization import organization
from kernia_sqlalchemy import sqlalchemy_adapter

auth = init(KerniaOptions(
    database=await sqlalchemy_adapter(url="postgresql+asyncpg://localhost/app"),
    secret=os.environ["KERNIA_SECRET"],
    base_url="https://app.example.com",
    plugins=[email_and_password(), organization()],
))

# FastAPI:
from fastapi import FastAPI
from kernia_fastapi import mount_kernia, require_session

app = FastAPI()
mount_kernia(app, auth)                     # serves /api/auth/*

@app.get("/me")
async def me(session = Depends(require_session)):
    return {"user_id": session.user_id}
```

Your React/Vue/Svelte frontend points the **official Better Auth client** at this
server unchanged:

```ts
import { createAuthClient } from "better-auth/client";
export const authClient = createAuthClient({ baseURL: "/api/auth" });
```

## Why Kernia

- **Drop-in for the Better Auth ecosystem.** The official JS client and its
  framework hooks talk to a Kernia server with no shim. A headless wire-check
  (`examples/frontend/scripts/wire-check.mjs`) drives the real client against
  the example server on every change.
- **Batteries included.** 27 built-in plugins + 7 standalone packages: from
  email/password to full OIDC provider, SAML SSO, SCIM provisioning, and Stripe
  seat-based billing.
- **One schema, many databases.** Memory, SQLAlchemy (Postgres/MySQL/SQLite),
  and MongoDB adapters behind a single `CustomAdapter` protocol. A 64-case
  conformance suite runs against each.
- **Security by default.** Argon2id password hashing, HMAC-signed cookies,
  CSRF/trusted-origins, PKCE-bound OAuth state, AES-GCM token encryption at rest,
  rate limiting, and a real WebAuthn verifier.
- **Frontends generate their own SDK.** The `open_api` plugin emits a validated
  OpenAPI 3.1 document at `/api/auth/openapi.json` — no bespoke client to ship.

## Install

> **Not yet on PyPI.** Install from source ahead of the first release.

```bash
git clone https://github.com/advantch/kernia
cd kernia
uv sync
uv pip install -e packages/core -e packages/sqlalchemy_adapter -e packages/fastapi_integration
```

Once released:

```bash
uv add kernia kernia-sqlalchemy kernia-fastapi
```

## Quickstart

Scaffold an app with the CLI:

```bash
kernia init --adapter sqlite --framework fastapi   # writes auth.py + .env.example
kernia secret                                      # generate KERNIA_SECRET
kernia generate                                    # emit an Alembic migration
kernia migrate                                     # apply it
```

Or run the full SaaS reference app (FastAPI backend + shadcn/React frontend):

```bash
# terminal 1 — backend on :5050
uv run uvicorn examples.backend.app:app --port 5050 --reload

# terminal 2 — frontend on :5173
cd examples/frontend && pnpm install && pnpm dev
```

See [`examples/`](./examples) for the full walkthrough.

## What's included

**Built-in plugins** (`packages/core/src/kernia/plugins/`):
`access`, `additional_fields`, `admin`, `anonymous`, `bearer`, `captcha`,
`custom_session`, `device_authorization`, `email_otp`, `email_password`,
`generic_oauth`, `haveibeenpwned`, `jwt`, `last_login_method`, `magic_link`,
`mcp`, `multi_session`, `oauth_proxy`, `oidc_provider`, `one_tap`,
`one_time_token`, `open_api`, `organization`, `phone_number`, `siwe`,
`two_factor`, `username`.

**Standalone packages:** `api_key`, `passkey`, `sso` (SAML + OIDC),
`oauth_provider` (full OIDC issuer), `scim`, `stripe`, `redis_storage`.

**Adapters:** `memory`, `sqlalchemy` (Postgres/MySQL/SQLite + transactions, joins,
case-insensitive, UUID PKs), `mongo` (motor).

**Social providers:** 35 built-in (Apple, GitHub, Google, Discord, Microsoft,
Slack, …) plus generic-OAuth constructors for Auth0, Okta, Keycloak, Entra ID,
Patreon, Line, Gumroad, HubSpot.

**Server integrations:** FastAPI, Starlette, Django (async-to-sync bridge).

**CLI:** `kernia init | generate | migrate | secret | info`.

## Security

Argon2id (with scrypt verify-fallback and lazy `needs_rehash` upgrade),
HMAC-SHA256 cookie signing wire-compatible with the Better Auth JS client,
signed PKCE-bound OAuth `state`, pure-stdlib RS256 id_token verification + authlib
ES256/EdDSA issuance, AES-GCM OAuth-token-at-rest encryption, trusted-origins CSRF
(on by default), cookie-secret rotation, InMemory + Redis rate limiting, HIBP
k-anonymity checks, and captcha middleware (reCAPTCHA v2/v3, Turnstile, hCaptcha).

Found a vulnerability? See [SECURITY.md](./SECURITY.md) — please report privately.

## Testing

```bash
uv run pytest e2e/ -q              # cross-adapter + per-plugin + integration
```

- `examples/frontend/scripts/wire-check.mjs` drives the official Better Auth JS
  client through sign-up → session → sign-out → sign-in → organization
  create/list, plus a negative-credentials case — proof the wire protocol holds
  end to end.

Tiers: unit tests in `packages/<pkg>/tests/`, plugin integration in
`e2e/plugins/`, cross-cutting flows in `e2e/integration/`, adapter conformance in
`e2e/adapter/`. Docker-gated suites (Postgres/MySQL/Mongo/Redis) skip cleanly when
Docker is unavailable.

## Repository layout

```
.
├── packages/
│   ├── core/                         # kernia: 27 plugins + 35 social providers + i18n
│   ├── memory_adapter/  sqlalchemy_adapter/  mongo_adapter/  redis_storage/
│   ├── api_key/  passkey/  sso/  oauth_provider/  scim/  stripe/  mcp/
│   ├── fastapi_integration/  starlette_integration/  django_integration/
│   └── cli/  test_utils/
├── e2e/                              # adapter/ · plugins/ · integration/
├── apps/docs/                        # Fumadocs + Next.js docs site (Vercel)
├── examples/                         # FastAPI + React SaaS reference app
└── .github/workflows/                # ci.yml · security.yml · publish.yml
```

## Contributing

Issues and PRs welcome. Read [CONTRIBUTING.md](./CONTRIBUTING.md) for the
workspace layout, quality gates, and conventions. By contributing you
agree to the [Code of Conduct](./CODE_OF_CONDUCT.md).

## License

[MIT](./LICENSE) © Advantch. Kernia is an independent implementation and is not
affiliated with or endorsed by the Better Auth project.
