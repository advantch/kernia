"""FastAPI integration: mount + use the session dependency in a downstream route."""

from __future__ import annotations

import pytest


@pytest.fixture
def app_and_client():
    pytest.importorskip("fastapi")
    httpx = pytest.importorskip("httpx")
    from fastapi import Depends, FastAPI
    from kernia.auth import init
    from kernia.plugins import email_and_password
    from kernia.types.init_options import KerniaOptions
    from kernia_fastapi import (
        get_session,
        mount_kernia,
        require_session,
    )
    from kernia_memory_adapter import memory_adapter

    auth = init(
        KerniaOptions(
            database=memory_adapter(),
            secret="test-secret",
            plugins=[email_and_password()],
        )
    )
    app = FastAPI()
    mount_kernia(app, auth)

    @app.get("/me")
    async def me(session=Depends(require_session)) -> dict:
        return {"user_id": session.user_id}

    @app.get("/maybe-me")
    async def maybe_me(session=Depends(get_session)) -> dict:
        return {"signed_in": session is not None}

    transport = httpx.ASGITransport(app=app)
    client = httpx.AsyncClient(transport=transport, base_url="http://test")
    return app, client


async def test_signup_via_mounted_kernia_then_dependency(app_and_client) -> None:
    _, client = app_and_client
    async with client:
        r = await client.post(
            "/api/auth/sign-up/email",
            json={"email": "x@example.com", "password": "correcthorse"},
        )
        assert r.status_code == 200, r.text
        # /maybe-me reflects session
        r = await client.get("/maybe-me")
        assert r.json() == {"signed_in": True}
        # /me returns user id
        r = await client.get("/me")
        assert r.status_code == 200
        assert "user_id" in r.json()
        # Sign out, then /me 401s
        r = await client.post("/api/auth/sign-out")
        assert r.status_code == 200
        r = await client.get("/me")
        assert r.status_code == 401


async def test_require_session_blocks_unauthenticated(app_and_client) -> None:
    _, client = app_and_client
    async with client:
        r = await client.get("/me")
        assert r.status_code == 401


async def test_expired_session_rejected_by_dependencies(app_and_client) -> None:
    """An expired session must read as absent through get_session/require_session."""
    import time

    from kernia.types.adapter import Where

    app, client = app_and_client
    async with client:
        r = await client.post(
            "/api/auth/sign-up/email",
            json={"email": "stale@example.com", "password": "correcthorse"},
        )
        assert r.status_code == 200, r.text
        user_id = r.json()["user"]["id"]

        # Backdate the session row one hour into the past.
        auth = app.state.kernia
        await auth.context.adapter.update(
            model="session",
            where=(Where(field="userId", value=user_id),),
            update={"expiresAt": int(time.time()) - 3600},
        )

        r = await client.get("/maybe-me")
        assert r.json() == {"signed_in": False}
        r = await client.get("/me")
        assert r.status_code == 401

        # The stale row was deleted on first use (replay-proof).
        row = await auth.context.adapter.find_one(
            model="session",
            where=(Where(field="userId", value=user_id),),
        )
        assert row is None
