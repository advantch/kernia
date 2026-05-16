# better-auth-python

A Python port of [better-auth](https://better-auth.com), the framework-agnostic
authentication library for TypeScript. Same plugin model, same database schema, same
endpoints — wired for ASGI apps (FastAPI, Starlette) and Django.

## Highlights

- **Framework-agnostic core.** A pure-Python `init()` returns an ASGI router you can
  mount on FastAPI, Starlette, or wrap with a Django adapter.
- **Plugins are first-class.** Drop-in support for email/password, OAuth, magic links,
  passkeys, organizations, SSO, SCIM, Stripe, and more — same constructor names as
  the JS reference.
- **One schema, many adapters.** Memory, SQLAlchemy (SQLite/Postgres/MySQL), MongoDB,
  Redis (storage), pluggable via the `CustomAdapter` protocol.
- **Migrations via Alembic.** `better-auth generate` emits an Alembic revision; the
  schema is the merge of core + every plugin's contributions.
- **Wire-compatible.** Better-auth JS clients can talk to a Python server unchanged.

## Install

```bash
pip install better-auth-python better-auth-cli
```

## 30-second tour

```python
from better_auth import BetterAuthOptions
from better_auth.auth import init
from better_auth.plugins.email_password import email_and_password
from better_auth_memory_adapter import memory_adapter

auth = init(
    BetterAuthOptions(
        database=memory_adapter(),
        secret="change-me",
        plugins=[email_and_password()],
    )
)
```

Mount on FastAPI:

```python
from fastapi import FastAPI
from better_auth.fastapi_integration import mount_auth

app = FastAPI()
mount_auth(app, auth)
```

That's it. `POST /api/auth/sign-up/email`, `POST /api/auth/sign-in/email`, sessions
in HttpOnly cookies, the same shape as the JS reference.

## Next

- [Getting started](getting-started.md) — full quickstart with the CLI.
- [Plugins](plugins/index.md) — what each plugin contributes.
- [OpenAPI](openapi.md) — auto-generated API docs.
