"""Vercel Python serverless entry for the Kernia demo backend.

Vercel detects the module-level `app` (an ASGI FastAPI app) and serves it. All
`/api/*` requests are routed here by `examples/vercel.json`; the FastAPI app
mounts Kernia at `/api/auth/*` and adds a few demo helper routes.

This demo uses the in-memory adapter, so data resets when the serverless
instance goes cold. That's fine for a click-through demo — do not deploy this
configuration for real use.
"""

from __future__ import annotations

import os

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from kernia import KerniaOptions
from kernia.auth import init
from kernia.events import get_bus
from kernia.plugins import email_and_password
from kernia.plugins.admin import admin
from kernia.plugins.admin_config import AdminConfigOptions, admin_config
from kernia.plugins.email_otp import email_otp
from kernia.plugins.magic_link import magic_link
from kernia.plugins.open_api import open_api
from kernia.plugins.organization import organization
from kernia.types.adapter import Where
from kernia.types.context import Session
from kernia_api_key import api_key
from kernia_fastapi import get_session, mount_kernia, require_session
from kernia_memory_adapter import memory_adapter
from kernia_stripe import StripeClient, StripeOptions, StripePlan, stripe

try:
    from kernia_test_utils import MockStripe
except Exception:  # pragma: no cover
    MockStripe = None  # type: ignore[assignment]


def build_app() -> FastAPI:
    secret = os.environ.get("KERNIA_SECRET", "demo-secret-change-me")
    # Vercel injects the deployment domain; prefer the stable production URL.
    vercel_host = (
        os.environ.get("VERCEL_PROJECT_PRODUCTION_URL")
        or os.environ.get("VERCEL_URL")
    )
    base_url = os.environ.get("KERNIA_BASE_URL") or (
        f"https://{vercel_host}" if vercel_host else "http://localhost:5050"
    )

    async def _log_magic_link(email: str, url: str, token: str) -> None:
        print(f"[kernia demo] magic link for {email}: {url}")

    async def _log_otp(email: str, otp: str, purpose: str) -> None:
        print(f"[kernia demo] otp for {email}: {otp} ({purpose})")

    # No real Stripe key in the demo — use the in-process mock transport.
    mock = MockStripe() if MockStripe is not None else None
    stripe_client = StripeClient(
        api_key="sk_test_demo",
        transport=mock.mock_transport() if mock is not None else None,
    )

    auth = init(
        KerniaOptions(
            database=memory_adapter(),
            secret=secret,
            base_url=base_url,
            base_path="/api/auth",
            trusted_origins=[base_url],
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
                        webhook_secret="whsec_demo",
                        subscription_for="organization",
                        plans={
                            "starter": StripePlan(
                                name="starter", price_id="price_starter"
                            ),
                            "team": StripePlan(
                                name="team",
                                price_id="price_team_base",
                                seats=True,
                                seat_price_id="price_team_seat",
                            ),
                        },
                    )
                ),
                open_api(),
            ],
            advanced={
                "magic-link": {"send_magic_link": _log_magic_link},
                "email-otp": {"send_otp": _log_otp},
                # The browser calls /api/* same-origin (cookies are SameSite=Lax),
                # but Vercel's preview domains rotate, so we relax the origin check
                # for the demo. Production apps keep this ON with a fixed base_url.
                "disable_csrf_check": True,
            },
        )
    )

    application = FastAPI(title="Kernia demo")
    application.add_middleware(
        CORSMiddleware,
        allow_origins=[base_url],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["set-cookie"],
    )
    mount_kernia(application, auth)

    # Demo event tap so the frontend Events tab can show the bus live.
    event_log: list[dict] = []

    async def _on_member_event(payload) -> None:  # type: ignore[no-untyped-def]
        event_log.append(
            {
                "event": f"organization.member.{payload.action}",
                "organization_id": payload.organization_id,
                "user_id": payload.user_id,
                "role": payload.role,
            }
        )

    bus = get_bus(auth.context)
    bus.on("organization.member.added", _on_member_event)
    bus.on("organization.member.removed", _on_member_event)
    bus.on("organization.member.updated", _on_member_event)

    @application.get("/api/me")
    async def me(session: Session = Depends(require_session)) -> dict:
        user = await auth.context.adapter.find_one(
            model="user", where=(Where(field="id", value=session.user_id),)
        )
        return {"session_id": session.id, "user": user}

    @application.get("/api/whoami")
    async def whoami(session=Depends(get_session)) -> dict:
        return {"signed_in": session is not None}

    @application.get("/api/demo/events")
    async def demo_events() -> dict:
        return {"events": list(event_log[-50:])}

    return application


app = build_app()
