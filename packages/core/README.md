# kernia

Framework-agnostic authentication core for Python: email/password, sessions, OAuth, and a plugin system. Wire-compatible with the official Better Auth JavaScript client, so an existing frontend can talk to a Kernia server unchanged.

Kernia is a framework-agnostic authentication library for Python. See [kernia.dev](https://kernia.dev).

## Features

- Email/password sign-up and sign-in with Argon2id hashing
- HMAC-signed session cookies and CSRF/trusted-origins protection
- OAuth 2.0 social sign-in with 35 built-in providers plus generic OAuth
- A plugin system: organizations, admin, magic links, email OTP, two-factor, JWT, OpenAPI, and more
- One schema across memory, SQLAlchemy, and MongoDB adapters
- Wire-compatible with the official Better Auth JavaScript client

## Installation

    pip install kernia

Adapters, server integrations, and optional plugins ship in the same
distribution as extras. Install only what you use:

    pip install "kernia[fastapi,sqlalchemy]"

Available extras: `jwt`, `passkey`, `sso`, `oauth-provider`, `stripe`, `mcp`,
`sqlalchemy`, `mongo`, `redis`, `fastapi`, `starlette`, `django`, and `all`. Each
pulls in its own third-party requirements; the import paths are unchanged
(`from kernia_fastapi import mount_kernia`, `from kernia_sqlalchemy import
sqlalchemy_adapter`, and so on).

## Usage

```python
import os
from kernia.auth import init
from kernia.plugins import email_and_password
from kernia.plugins.organization import organization
from kernia.types.init_options import KerniaOptions
from kernia_memory_adapter import memory_adapter

auth = init(
    KerniaOptions(
        database=memory_adapter(),
        secret=os.environ["KERNIA_SECRET"],
        base_url="http://localhost:8000",
        base_path="/api/auth",
        plugins=[email_and_password(), organization()],
    )
)
```

Mount it on a FastAPI app with `kernia-fastapi`:

```python
from fastapi import Depends, FastAPI
from kernia_fastapi import mount_kernia, require_session

app = FastAPI()
mount_kernia(app, auth)  # serves /api/auth/*

@app.get("/me")
async def me(session=Depends(require_session)):
    return {"user_id": session.user_id}
```

Point the official Better Auth JavaScript client at `/api/auth` and it works without a shim.

## Documentation

Full documentation at [kernia.dev/docs](https://kernia.dev/docs). Source at [github.com/advantch/kernia](https://github.com/advantch/kernia).

## License

MIT
