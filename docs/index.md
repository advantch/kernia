# kernia

Kernia is a Python implementation compatible with [Better Auth](https://better-auth.com), the framework-agnostic
authentication library for TypeScript. Same plugin model, same database schema, same
endpoints — wired for ASGI apps (FastAPI, Starlette) and Django.

## Highlights

- **Framework-agnostic core.** A pure-Python `init()` returns an ASGI router you can
  mount on FastAPI, Starlette, or wrap with a Django adapter.
- **Plugins are first-class.** Drop-in support for email/password, OAuth, magic links,
  passkeys, organizations, SSO, SCIM, Stripe, and more — same constructor names as
  the JS reference.
- **SaaS reference app.** The FastAPI + Vite demo includes login, logout,
  settings, API keys, sessions, admin config, Stripe catalog import, and billing
  entitlement screens backed by real Kernia APIs.
- **One schema, many adapters.** Memory, SQLAlchemy (SQLite/Postgres/MySQL), MongoDB,
  Redis (storage), pluggable via the `CustomAdapter` protocol.
- **Migrations via Alembic.** `kernia generate` emits an Alembic revision; the
  schema is the merge of core + every plugin's contributions.
- **Wire-compatible.** Better Auth JS clients can talk to a Python server unchanged.

## Install

```bash
pip install kernia kernia-cli
```

## 30-second tour

```python
from kernia import KerniaOptions
from kernia.auth import init
from kernia.plugins.email_password import email_and_password
from kernia_memory_adapter import memory_adapter

auth = init(
    KerniaOptions(
        database=memory_adapter(),
        secret="change-me",
        plugins=[email_and_password()],
    )
)
```

Mount on FastAPI:

```python
from fastapi import FastAPI
from kernia_fastapi import mount_auth

app = FastAPI()
mount_auth(app, auth)
```

That's it. `POST /api/auth/sign-up/email`, `POST /api/auth/sign-in/email`, sessions
in HttpOnly cookies, the same shape as the JS reference.

## Next

- [Getting started](getting-started.md) — full quickstart with the CLI.
- [FastAPI SaaS demo](demo.md) — real backend and frontend walkthrough.
- [Admin config](admin-config.md) — persisted runtime config for login methods,
  email clients, and Stripe settings.
- [Billing and entitlements](billing.md) — Stripe import, features, balances, and
  usage tracking.
- [Plugins](plugins/index.md) — what each plugin contributes.
- [OpenAPI](openapi.md) — auto-generated API docs.
