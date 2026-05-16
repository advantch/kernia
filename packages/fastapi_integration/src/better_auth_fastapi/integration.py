"""FastAPI mount + session dependencies."""

from __future__ import annotations

from fastapi import FastAPI, HTTPException, Request

from better_auth.auth import BetterAuth
from better_auth.cookies import verify
from better_auth.types.adapter import Where
from better_auth.types.context import Session


def mount_better_auth(app: FastAPI, auth: BetterAuth) -> None:
    """Mount the auth ASGI app at `auth.context.options.base_path`.

    All `/api/auth/*` routes flow through better-auth's router; the rest of the
    FastAPI app is untouched. We wrap the inner app so the base-path prefix is
    stripped before dispatch — that lets the router register routes by their
    canonical relative path (`/sign-in/email`).
    """
    base_path = auth.context.options.base_path.rstrip("/")
    inner = auth.router.mount()

    async def stripped(scope, receive, send):  # type: ignore[no-untyped-def]
        if scope["type"] == "http" and scope["path"].startswith(base_path):
            scope = dict(scope)
            scope["path"] = scope["path"][len(base_path):] or "/"
        await inner(scope, receive, send)

    app.mount(base_path, stripped)
    app.state.better_auth = auth


async def get_session(request: Request) -> Session | None:
    """FastAPI dependency: returns the active session (or None)."""
    auth: BetterAuth = request.app.state.better_auth
    cookie = request.cookies.get("better-auth.session_token")
    if not cookie:
        return None
    token = verify(cookie, secret=auth.context.secret)
    if not token:
        return None
    row = await auth.context.adapter.find_one(
        model="session",
        where=(Where(field="token", value=token),),
    )
    if row is None:
        return None
    return Session(
        id=row["id"],
        user_id=row["userId"],
        expires_at=int(row["expiresAt"]),
        token=row["token"],
        ip_address=row.get("ipAddress"),
        user_agent=row.get("userAgent"),
    )


async def require_session(request: Request) -> Session:
    """FastAPI dependency: 401 if no session."""
    session = await get_session(request)
    if session is None:
        raise HTTPException(status_code=401, detail="UNAUTHORIZED")
    return session
