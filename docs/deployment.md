# Deployment

Kernia runs as an ASGI app mounted into FastAPI or Starlette, or through the
Django integration.

## Production checklist

- Use a stable `KERNIA_SECRET`; rotate with multiple configured secrets when
  needed.
- Use SQLAlchemy with Postgres/MySQL/SQLite or the Mongo adapter for persistent
  user/session data.
- Run `kernia generate` and `kernia migrate` after changing plugin schema.
- Set trusted origins for browser clients.
- Configure external providers through environment variables or persisted admin
  config.
- Keep Stripe webhook secrets write-only and verify webhooks at the edge.

## FastAPI

```python
from fastapi import FastAPI
from kernia_fastapi import mount_auth
from auth import auth

app = FastAPI()
mount_auth(app, auth, prefix="/api/auth")
```

## Health checks

Expose a normal application health route outside Kernia. Auth routes should stay
behind the same proxy and cookie domain as your product frontend.
