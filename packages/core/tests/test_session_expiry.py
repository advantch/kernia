"""Regression tests for session-expiry enforcement at the router chokepoint.

Guards against a library-wide auth bypass: before the fix, `_attach_session` read
`expiresAt` into the `Session` object but never compared it to the current time,
so a session whose `expiresAt` was in the past STILL authenticated — `/get-session`
returned the full user and every `requires_session=True` route returned 200.

Upstream Better Auth (`api/routes/session.ts` → `getSessionFromCtx`) treats an
expired session as no session (`session.expiresAt < new Date()` → `return null`),
deletes the stale row (`internalAdapter.deleteSession(token)`), AND clears the
session cookies (`deleteSessionCookie(ctx)` — `session_token` + `dont_remember`
with Max-Age=0, the same clearing contract sign-out uses). These tests assert all
three behaviours, driving real HTTP requests through the mounted ASGI app.
"""

from __future__ import annotations

import time

from kernia.auth import init
from kernia.plugins.email_password import email_and_password
from kernia.types.adapter import Where
from kernia.types.init_options import KerniaOptions
from kernia_memory_adapter import memory_adapter
from kernia_test_utils import ASGIDriver


def _build_driver() -> tuple[ASGIDriver, object]:
    auth = init(
        KerniaOptions(
            database=memory_adapter(),
            secret="test-secret-key",
            plugins=[email_and_password()],
        )
    )
    return ASGIDriver(app=auth.router.mount()), auth


async def _sign_up(driver: ASGIDriver) -> dict[str, object]:
    r = await driver.request(
        "POST",
        "/sign-up/email",
        json_body={"email": "expired@example.com", "password": "secretpass"},
    )
    assert r.status == 200, r.json()
    # Auto sign-in is on by default: the session_token cookie is now in the jar.
    assert "better-auth.session_token" in driver.cookies
    return r.json()


async def test_valid_session_authenticates_baseline() -> None:
    """Sanity check: while `expiresAt` is in the future, the cookie authenticates.

    This pins the precondition so the expiry assertions below can't pass for the
    wrong reason (e.g. a broken cookie jar).
    """
    driver, _auth = _build_driver()
    signup = await _sign_up(driver)
    user_id = signup["user"]["id"]  # type: ignore[index]

    got = await driver.request("GET", "/get-session")
    assert got.status == 200
    assert got.json() is not None
    assert got.json()["user"]["id"] == user_id

    listed = await driver.request("GET", "/list-sessions")
    assert listed.status == 200
    assert len(listed.json()) == 1


async def _expire_current_session(auth, user_id: str) -> str:
    """Force the user's session row ~1 hour into the past; returns its token."""
    row = await auth.context.adapter.find_one(
        model="session",
        where=(Where(field="userId", value=user_id),),
    )
    assert row is not None
    await auth.context.adapter.update(
        model="session",
        where=(Where(field="id", value=row["id"]),),
        update={"expiresAt": int(time.time()) - 3600},
    )
    return row["token"]


async def test_expired_session_is_treated_as_absent_and_cleaned_up() -> None:
    driver, auth = _build_driver()
    signup = await _sign_up(driver)
    user_id = signup["user"]["id"]  # type: ignore[index]
    token = await _expire_current_session(auth, user_id)

    # /get-session: an expired session must read as "no session" → null body.
    got = await driver.request("GET", "/get-session")
    assert got.status == 200
    assert got.json() is None

    # The response must clear the dead cookies (Max-Age=0 → empty value), the
    # same contract sign-out uses; the driver's jar drops them accordingly.
    cleared = got.set_cookies()
    assert cleared.get("better-auth.session_token") == ""
    assert cleared.get("better-auth.dont_remember") == ""
    assert "better-auth.session_token" not in driver.cookies

    # The expired row must have been deleted from the adapter (cleanup parity).
    remaining = await auth.context.adapter.find_one(
        model="session",
        where=(Where(field="token", value=token),),
    )
    assert remaining is None

    by_user = await auth.context.adapter.find_many(
        model="session",
        where=(Where(field="userId", value=user_id),),
        sort_by=None,
    )
    assert by_user == []


async def test_expired_session_rejected_by_requires_session_route() -> None:
    """A protected route hit directly with an expired cookie must 401.

    Exercises the expired path on a `requires_session=True` endpoint (not via
    /get-session first), so the 401 comes from expiry enforcement — the cookie
    is still present and well-signed when the request is made.
    """
    driver, auth = _build_driver()
    signup = await _sign_up(driver)
    user_id = signup["user"]["id"]  # type: ignore[index]
    token = await _expire_current_session(auth, user_id)

    listed = await driver.request("GET", "/list-sessions")
    assert listed.status == 401
    assert listed.json()["code"] == "UNAUTHORIZED"
    # The 401 also instructs the client to drop the dead cookie...
    assert listed.set_cookies().get("better-auth.session_token") == ""
    # ...and the stale row is gone.
    remaining = await auth.context.adapter.find_one(
        model="session",
        where=(Where(field="token", value=token),),
    )
    assert remaining is None


async def test_session_one_second_in_the_future_still_valid() -> None:
    """Boundary: a session that has not yet expired stays valid and is not deleted.

    Protects against an off-by-one that would treat a barely-valid session as
    expired (the comparison is a strict `expiresAt < now`).
    """
    driver, auth = _build_driver()
    signup = await _sign_up(driver)
    user_id = signup["user"]["id"]  # type: ignore[index]

    row = await auth.context.adapter.find_one(
        model="session",
        where=(Where(field="userId", value=user_id),),
    )
    assert row is not None
    await auth.context.adapter.update(
        model="session",
        where=(Where(field="id", value=row["id"]),),
        update={"expiresAt": int(time.time()) + 60},
    )

    got = await driver.request("GET", "/get-session")
    assert got.status == 200
    assert got.json() is not None
    assert got.json()["user"]["id"] == user_id

    # Still present in the adapter — a valid session is never cleaned up.
    still_there = await auth.context.adapter.find_one(
        model="session",
        where=(Where(field="token", value=row["token"]),),
    )
    assert still_there is not None
