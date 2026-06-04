"""Vercel Python serverless entry for the Kernia demo backend.

Vercel detects the module-level `app` (an ASGI FastAPI app) and serves it. All
`/api/*` requests are routed here by `vercel.json`; the FastAPI app mounts
Kernia at `/api/auth/*` and adds a few demo helper routes.

Storage: if `DATABASE_URL` is set (the Prisma Postgres provisioned for this
project), Kernia runs on the SQLAlchemy adapter against that Postgres and data
persists. Otherwise it falls back to the in-memory adapter (local dev only).
"""

from __future__ import annotations

import asyncio
import os
import re

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from kernia import KerniaOptions
from kernia.auth import init
from kernia.db.migrations import resolve_full_schema
from kernia.db.schema import CORE_MODELS
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


def _postgres_adapter(plugins: list) -> object:
    """Build a SQLAlchemy adapter against DATABASE_URL and materialize the full
    schema (core tables + every plugin's tables/extensions). Returns the adapter.
    """
    from sqlalchemy.ext.asyncio import create_async_engine
    from sqlalchemy.pool import NullPool

    from kernia_sqlalchemy.adapter import SQLAlchemyAdapter, build_metadata

    raw = os.environ["DATABASE_URL"]
    # postgres://...?sslmode=require  ->  postgresql+asyncpg://...  (+ ssl via connect_args)
    url = re.sub(r"^postgres(ql)?://", "postgresql+asyncpg://", raw)
    url = re.sub(r"[?&]sslmode=\w+", "", url)

    models = resolve_full_schema(CORE_MODELS, plugins)
    metadata = build_metadata(models)
    # NullPool: serverless functions can't keep a pool warm and asyncpg
    # connections are loop-bound — open one per request, in that request's loop.
    engine = create_async_engine(
        url, poolclass=NullPool, connect_args={"ssl": True}, future=True
    )
    adapter = SQLAlchemyAdapter(engine=engine, metadata=metadata, models=models)

    async def _create_tables() -> None:
        async with engine.begin() as conn:
            await conn.run_sync(metadata.create_all)  # idempotent (checkfirst)

    # Run in a dedicated thread so `asyncio.run` works regardless of whether the
    # importing thread already has a running event loop (Vercel cold start vs.
    # in-process reload). The thread has no loop of its own.
    import threading

    error: list[BaseException] = []

    def _runner() -> None:
        try:
            asyncio.run(_create_tables())
        except BaseException as exc:  # noqa: BLE001
            error.append(exc)

    t = threading.Thread(target=_runner)
    t.start()
    t.join()
    if error:
        raise error[0]
    return adapter


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

    plugins = [
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
                    "starter": StripePlan(name="starter", price_id="price_starter"),
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
    ]

    # Real Postgres when DATABASE_URL is present (persistent); else in-memory.
    if os.environ.get("DATABASE_URL"):
        database = _postgres_adapter(plugins)
    else:
        database = memory_adapter()

    auth = init(
        KerniaOptions(
            database=database,
            secret=secret,
            base_url=base_url,
            base_path="/api/auth",
            trusted_origins=[base_url],
            plugins=plugins,
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
