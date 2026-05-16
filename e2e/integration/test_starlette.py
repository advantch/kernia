"""Starlette integration: mount + use the session helpers in a downstream route."""

from __future__ import annotations

import pytest


@pytest.fixture
def app_and_client():
    starlette = pytest.importorskip("starlette")
    httpx = pytest.importorskip("httpx")
    from starlette.applications import Starlette
    from starlette.requests import Request
    from starlette.responses import JSONResponse
    from starlette.routing import Route

    from better_auth.auth import init
    from better_auth.plugins.email_password import email_and_password
    from better_auth.types.init_options import BetterAuthOptions
    from better_auth_memory_adapter import memory_adapter
    from better_auth_starlette import (
        get_session,
        mount_better_auth,
        require_session,
    )

    auth = init(
        BetterAuthOptions(
            database=memory_adapter(),
            secret="test-secret",
            plugins=[email_and_password()],
        )
    )

    async def me(request: Request) -> JSONResponse:
        session = await require_session(request)
        return JSONResponse({"user_id": session.user_id})

    async def maybe_me(request: Request) -> JSONResponse:
        session = await get_session(request)
        return JSONResponse({"signed_in": session is not None})

    app = Starlette(
        routes=[
            Route("/me", me),
            Route("/maybe-me", maybe_me),
        ]
    )
    mount_better_auth(app, auth)

    transport = httpx.ASGITransport(app=app)
    client = httpx.AsyncClient(transport=transport, base_url="http://test")
    return app, client


async def test_signup_via_mounted_better_auth_then_helper(app_and_client) -> None:
    _, client = app_and_client
    async with client:
        r = await client.post(
            "/api/auth/sign-up/email",
            json={"email": "x@example.com", "password": "correcthorse"},
        )
        assert r.status_code == 200, r.text
        r = await client.get("/maybe-me")
        assert r.json() == {"signed_in": True}
        r = await client.get("/me")
        assert r.status_code == 200
        assert "user_id" in r.json()
        r = await client.post("/api/auth/sign-out")
        assert r.status_code == 200
        r = await client.get("/me")
        assert r.status_code == 401


async def test_require_session_blocks_unauthenticated(app_and_client) -> None:
    _, client = app_and_client
    async with client:
        r = await client.get("/me")
        assert r.status_code == 401
