"""Reference FastAPI app demonstrating Kernia end-to-end.

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

from kernia.auth import init
from kernia.plugins import email_and_password
from kernia.plugins.admin import admin
from kernia.plugins.admin_config import AdminConfigOptions, admin_config
from kernia.plugins.email_otp import email_otp
from kernia.plugins.magic_link import magic_link
from kernia.plugins.organization import organization
from kernia.plugins.open_api import open_api
from kernia.social_providers import google
from kernia.types.context import Session
from kernia.types.init_options import KerniaOptions
from kernia_fastapi import get_session, mount_kernia, require_session
from kernia_api_key import api_key
from kernia_memory_adapter import memory_adapter
from kernia_stripe import StripeClient, StripeOptions, StripePlan, stripe

try:  # demo-only fallback when no real Stripe key is configured
    from kernia_test_utils import MockStripe
except Exception:  # pragma: no cover
    MockStripe = None  # type: ignore[assignment]


FRONTEND_ORIGIN = os.environ.get("FRONTEND_ORIGIN", "http://localhost:5173")
DEV_FRONTEND_ORIGINS = {
    FRONTEND_ORIGIN,
    "http://localhost:5173",
    "http://127.0.0.1:5173",
}


def build_app() -> FastAPI:
    social_providers: dict = {}
    google_id = os.environ.get("GOOGLE_CLIENT_ID")
    google_secret = os.environ.get("GOOGLE_CLIENT_SECRET")
    if google_id and google_secret:
        social_providers["google"] = google(
            client_id=google_id, client_secret=google_secret
        )

    async def _log_magic_link(email: str, url: str, token: str) -> None:
        print(f"[kernia demo] magic link for {email}: {url} ({token})")

    async def _log_otp(email: str, otp: str, purpose: str) -> None:
        print(f"[kernia demo] email otp for {email}: {otp} ({purpose})")

    stripe_key = os.environ.get("STRIPE_API_KEY", "")
    if stripe_key:
        stripe_client = StripeClient(api_key=stripe_key)
    else:
        mock = MockStripe() if MockStripe is not None else None
        stripe_client = StripeClient(
            api_key="sk_test_demo",
            transport=mock.mock_transport() if mock is not None else None,
        )

    auth = init(
        KerniaOptions(
            database=memory_adapter(),
            secret=os.environ.get("KERNIA_SECRET", "dev-only-secret-change-me"),
            base_url="http://localhost:8000",
            base_path="/api/auth",
            trusted_origins=[*DEV_FRONTEND_ORIGINS, "http://localhost:8000", "http://127.0.0.1:8000"],
            plugins=[
                admin_config(AdminConfigOptions(allow_any_authenticated=True)),
                email_and_password(),
                magic_link(),
                email_otp(),
                organization(),
                admin(),
                api_key(),
                stripe(
                    StripeOptions(
                        stripe_client=stripe_client,
                        webhook_secret=os.environ.get("STRIPE_WEBHOOK_SECRET", "whsec_demo"),
                        plans={
                            "starter": StripePlan(
                                name="starter",
                                price_id="price_starter_monthly",
                                lookup_key="starter-monthly",
                            )
                        },
                    )
                ),
                open_api(),
            ],
            social_providers=social_providers,
            advanced={
                "magic-link": {"send_magic_link": _log_magic_link},
                "email-otp": {"send_otp": _log_otp},
                # Frontend handles same-site cookies; we want the cookie back
                # via fetch credentials: include — so SameSite=Lax is enough.
            },
        )
    )

    app = FastAPI(title="kernia example")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[*DEV_FRONTEND_ORIGINS],
        allow_credentials=True,  # required so cookies flow cross-origin
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["set-cookie"],
    )

    mount_kernia(app, auth)

    @app.get("/")
    async def root() -> dict:
        return {"name": "kernia example", "auth_base": "/api/auth"}

    @app.get("/api/me")
    async def me(session: Annotated[Session, Depends(require_session)]) -> dict:
        user = await auth.context.adapter.find_one(
            model="user",
            where=(
                __import__("kernia.types.adapter", fromlist=["Where"]).Where(
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
