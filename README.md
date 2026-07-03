<div align="center">

# Kernia

**A type-safe, plugin-based authentication library for FastAPI, Starlette, and Django.**

[![PyPI](https://img.shields.io/pypi/v/kernia.svg)](https://pypi.org/project/kernia/)
[![CI](https://github.com/advantch/kernia/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/advantch/kernia/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12-blue.svg)](https://pypi.org/project/kernia/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](./LICENSE)

[Documentation](https://kernia.dev/docs) ·
[Blog](https://kernia.dev/blog) ·
[Quickstart](#quickstart) ·
[Plugins and adapters](#plugins-and-adapters) ·
[Examples](./examples)

</div>

---

Authentication in Kernia is a set of plugins you compose, not a framework you inherit from. You call `init` with options and the plugins you want, and you get back an `auth` object that serves the whole auth surface under `/api/auth/*`. Email and password is a plugin; so is everything past it, from magic links and passkeys to organizations, SSO, SCIM, and Stripe billing. Each plugin owns its own routes, database tables, rate-limit rules, and error codes, so adding a capability is adding a constructor to a list rather than starting another rewrite. Security is on by default: Argon2id hashing, HMAC-signed cookies, CSRF protection, PKCE-bound OAuth state, and AES-GCM encryption of OAuth tokens at rest are not opt-in homework.

## Install

```bash
pip install kernia
```

Adapters, framework integrations, and heavier plugins ship as extras of the single `kernia` distribution, so you install only what a given app needs:

```bash
pip install "kernia[sqlalchemy,fastapi]"
```

The extras are `jwt`, `passkey`, `sso`, `oauth-provider`, `stripe`, `mcp`, `sqlalchemy`, `mongo`, `redis`, `fastapi`, `starlette`, `django`, and `all`. Import paths are the same however you install (`from kernia_fastapi import mount_kernia`, `from kernia_sqlalchemy import sqlalchemy_adapter`). The command-line tool (`kernia-cli`) and test helpers (`kernia-test-utils`) are separate distributions.

## Quickstart

Configure auth once, then mount it on your app. This is a minimal FastAPI setup with email and password over SQLAlchemy.

```python
import os

from kernia import KerniaOptions
from kernia.auth import init
from kernia.plugins import email_and_password
from kernia_sqlalchemy import sqlalchemy_adapter

auth = init(KerniaOptions(
    database=await sqlalchemy_adapter(url="postgresql+asyncpg://localhost/app"),
    secret=os.environ["KERNIA_SECRET"],
    base_url="https://app.example.com",
    plugins=[email_and_password()],
))
```

Mounting it is two lines. `mount_kernia` serves the whole auth surface under `/api/auth/*`, and `require_session` is a dependency that protects your own routes.

```python
from fastapi import Depends, FastAPI
from kernia_fastapi import mount_kernia, require_session
from kernia.types.context import Session

app = FastAPI()
mount_kernia(app, auth)                      # serves /api/auth/*

@app.get("/me")
async def me(session: Session = Depends(require_session)):
    return {"user_id": session.user_id}
```

`require_session` reads the signed cookie, loads the session, and returns 401 if there is none. `session.user_id` is typed. There is no middleware to register in a specific order and no request-local globals to thread through.

To scaffold a project from scratch, `kernia init --adapter sqlite --framework fastapi` writes an `auth.py` and `.env.example`, and `kernia secret`, `kernia generate`, and `kernia migrate` handle the secret and migrations. A full FastAPI-plus-React SaaS reference app lives in [`examples/`](./examples).

## Plugins and adapters

Every feature past email and password is a plugin you add to the `plugins` list, or a module you pull in as an extra. The database is chosen the same way, behind one adapter protocol, so a query that works on SQLite works the same on Postgres.

| Category | What ships |
| --- | --- |
| Auth plugins | email/password, magic link, email OTP, phone number, username, two-factor, anonymous, one-tap, SIWE, generic OAuth, and more |
| Organizations | multi-tenant organizations with teams and invitations, active-org on the session |
| Enterprise | SSO (SAML + OIDC), SCIM provisioning, API keys, OIDC provider, JWT/JWKS |
| Billing | Stripe seat-based billing |
| Passkeys | WebAuthn registration and login |
| Adapters | in-memory, SQLAlchemy (Postgres / MySQL / SQLite), MongoDB, Redis storage |
| Integrations | FastAPI, Starlette, Django |
| Providers | 35 built-in social providers (Apple, GitHub, Google, Discord, Microsoft, Slack, and others), plus generic-OAuth constructors for the rest |
| Tooling | `open_api` plugin emits a validated OpenAPI 3.1 spec at `/api/auth/openapi.json`; HaveIBeenPwned and captcha (reCAPTCHA, Turnstile, hCaptcha) middleware |

The adapter layer runs a conformance suite against every backend, so behavior stays consistent across databases. Kernia runs under our own applications.

## Client compatibility

Kernia's HTTP surface is compatible with the [Better Auth](https://better-auth.com) wire protocol (verified against 1.6.11), so that ecosystem's JavaScript client also works against a Kernia server:

```ts
import { createAuthClient } from "better-auth/client";
export const authClient = createAuthClient({ baseURL: "/api/auth" });
```

Teams moving a Node auth backend to Python can keep their existing frontend; the migration is server-side only.

## Documentation

- [Documentation](https://kernia.dev/docs) and [installation guide](https://kernia.dev/docs/installation)
- [Basic usage](https://kernia.dev/docs/basic-usage) and [plugin reference](https://kernia.dev/docs/plugins)
- [Blog](https://kernia.dev/blog)
- [Examples](./examples): FastAPI backend plus React frontend SaaS reference app

## Development

Kernia is a `uv` workspace. Clone it and install everything:

```bash
git clone https://github.com/advantch/kernia
cd kernia
uv sync
```

Run the tests, linter, and type checker:

```bash
uv run pytest e2e/ -q          # cross-adapter, per-plugin, and integration tests
uv run ruff check .            # lint
uv run ruff format --check .   # format
uv run mypy packages/core/src  # type check
```

Docker-gated suites for Postgres, MySQL, MongoDB, and Redis skip cleanly when Docker is unavailable. See [CONTRIBUTING.md](./CONTRIBUTING.md) for the workspace layout and conventions, [RELEASING.md](./RELEASING.md) for the release process, and [SECURITY.md](./SECURITY.md) to report a vulnerability privately.

## License

[MIT](./LICENSE) © Advantch. Kernia is an independent project and is not affiliated with or endorsed by the Better Auth project.
