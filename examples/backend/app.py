"""Reference FastAPI app demonstrating better-auth-python end-to-end.

This is what a consumer would write. Boots on port 8000. The vite frontend at
`../frontend/` points its `better-auth/client` at this server's `/api/auth/*`.

What's wired up:
  * email/password sign-up/in/out
  * organizations
  * open-api (so you can hit GET /api/auth/openapi.json)
  * trusted origins for the vite dev server
  * permissive CORS for browser tests

What's deliberately NOT wired up:
  * Google OAuth — needs real client_id/secret. Configurable via env vars; if
    GOOGLE_CLIENT_ID isn't set, the social-sign-in route returns 400.
"""

from __future__ import annotations

import os
from typing import Annotated

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from better_auth.auth import init
from better_auth.plugins import email_and_password
from better_auth.plugins.organization import organization
from better_auth.plugins.open_api import open_api
from better_auth.social_providers import google
from better_auth.types.context import Session
from better_auth.types.init_options import BetterAuthOptions
from better_auth_fastapi import get_session, mount_better_auth, require_session
from better_auth_memory_adapter import memory_adapter


FRONTEND_ORIGIN = os.environ.get("FRONTEND_ORIGIN", "http://localhost:5173")


def build_app() -> FastAPI:
    social_providers: dict = {}
    google_id = os.environ.get("GOOGLE_CLIENT_ID")
    google_secret = os.environ.get("GOOGLE_CLIENT_SECRET")
    if google_id and google_secret:
        social_providers["google"] = google(
            client_id=google_id, client_secret=google_secret
        )

    auth = init(
        BetterAuthOptions(
            database=memory_adapter(),
            secret=os.environ.get("BETTER_AUTH_SECRET", "dev-only-secret-change-me"),
            base_url="http://localhost:8000",
            base_path="/api/auth",
            trusted_origins=[FRONTEND_ORIGIN, "http://localhost:8000"],
            plugins=[email_and_password(), organization(), open_api()],
            social_providers=social_providers,
            advanced={
                # Frontend handles same-site cookies; we want the cookie back
                # via fetch credentials: include — so SameSite=Lax is enough.
            },
        )
    )

    app = FastAPI(title="better-auth-python example")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[FRONTEND_ORIGIN],
        allow_credentials=True,  # required so cookies flow cross-origin
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["set-cookie"],
    )

    mount_better_auth(app, auth)

    @app.get("/")
    async def root() -> dict:
        return {"name": "better-auth-python example", "auth_base": "/api/auth"}

    @app.get("/api/me")
    async def me(session: Annotated[Session, Depends(require_session)]) -> dict:
        user = await auth.context.adapter.find_one(
            model="user",
            where=(
                __import__("better_auth.types.adapter", fromlist=["Where"]).Where(
                    field="id", value=session.user_id
                ),
            ),
        )
        return {"session_id": session.id, "user": user}

    @app.get("/api/whoami")
    async def whoami(session=Depends(get_session)) -> dict:
        return {"signed_in": session is not None}

    return app


app = build_app()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="info")
