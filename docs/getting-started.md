# Getting started

This walks you from zero to a running better-auth server in five commands.

## 1. Install

```bash
pip install better-auth-python better-auth-cli
# Adapters (pick what you need):
pip install better-auth-memory-adapter      # for local dev
pip install better-auth-sqlalchemy          # SQLite/Postgres/MySQL
```

## 2. Scaffold

```bash
better-auth init --adapter sqlite --framework fastapi
```

This writes:

- `auth.py` — a minimal config with `init(...)` and an `email_and_password` plugin.
- `.env.example` — a generated `BETTER_AUTH_SECRET` and a `DATABASE_URL` placeholder.

Pick `--adapter memory | sqlite | postgres | mysql | mongo` and
`--framework fastapi | starlette | django | none`. Re-running refuses to overwrite
unless you pass `--force`.

## 3. Generate a migration

```bash
better-auth generate
```

This loads `auth.py`, walks every plugin's schema, and writes a single Alembic
revision into `alembic/versions/<rev>_better_auth_schema.py`. The revision id is a
12-character hash of the resolved schema shape, so re-running on an unchanged
config is a no-op.

## 4. Apply the migration

```bash
better-auth migrate
```

Runs `alembic upgrade head` against the database URL resolved from your config (or
`BETTER_AUTH_DATABASE_URL` / `DATABASE_URL` env var, or `--db-url`). Generates a
minimal `alembic/env.py` on first run.

## 5. Mount the auth router

For FastAPI:

```python
from fastapi import FastAPI
from better_auth.fastapi_integration import mount_auth
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
| `better-auth secret` | Generate a fresh 32-byte secret. |
| `better-auth info` | Print the loaded config: plugins, routes, adapter. |
| `better-auth info --dry-run --json` | Just print library version/platform. |
| `better-auth generate --output path` | Write the migration to a custom path. |
| `better-auth migrate --db-url ...` | Override the resolved DB URL. |
