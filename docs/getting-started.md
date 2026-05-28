# Getting started

This walks you from zero to a running Better Auth-compatible server in five commands.
Kernia is independent Python code; the compatibility point is the public HTTP
and cookie contract used by Better Auth clients.

## 1. Install

```bash
pip install kernia kernia-cli
# Adapters (pick what you need):
pip install kernia-memory-adapter      # for local dev
pip install kernia-sqlalchemy          # SQLite/Postgres/MySQL
```

## 2. Scaffold

```bash
kernia init --adapter sqlite --framework fastapi
```

This writes:

- `auth.py` — a minimal config with `init(...)` and an `email_and_password` plugin.
- `.env.example` — a generated `KERNIA_SECRET` and a `DATABASE_URL` placeholder.

Pick `--adapter memory | sqlite | postgres | mysql | mongo` and
`--framework fastapi | starlette | django | none`. Re-running refuses to overwrite
unless you pass `--force`.

## 3. Generate a migration

```bash
kernia generate
```

This loads `auth.py`, walks every plugin's schema, and writes a single Alembic
revision into `alembic/versions/<rev>_kernia_schema.py`. The revision id is a
12-character hash of the resolved schema shape, so re-running on an unchanged
config is a no-op.

## 4. Apply the migration

```bash
kernia migrate
```

Runs `alembic upgrade head` against the database URL resolved from your config (or
`KERNIA_DATABASE_URL` / `DATABASE_URL` env var, or `--db-url`). Generates a
minimal `alembic/env.py` on first run.

## 5. Mount the auth router

For FastAPI:

```python
from fastapi import FastAPI
from kernia_fastapi import mount_auth
from auth import auth

app = FastAPI()
mount_auth(app, auth)
```

Run it:

```bash
uvicorn main:app --reload
```

You now have:

- `POST /api/auth/sign-up/email`
- `POST /api/auth/sign-in/email`
- `POST /api/auth/sign-out`
- `GET  /api/auth/get-session`
- `POST /api/auth/forget-password`
- `POST /api/auth/reset-password`

…and whichever extra routes each plugin you registered contributes.

## Useful CLI commands

| Command | What it does |
| --- | --- |
| `kernia secret` | Generate a fresh 32-byte secret. |
| `kernia info` | Print the loaded config: plugins, routes, adapter. |
| `kernia info --dry-run --json` | Just print library version/platform. |
| `kernia generate --output path` | Write the migration to a custom path. |
| `kernia migrate --db-url ...` | Override the resolved DB URL. |

## Run the SaaS demo

```bash
uv run uvicorn examples.backend.app:app --host 127.0.0.1 --port 8000 --reload
cd examples/frontend
pnpm install
pnpm dev
```

The demo exposes settings, API keys, sessions, admin configuration, Stripe
catalog import, and billing entitlement screens over real Kernia routes.
