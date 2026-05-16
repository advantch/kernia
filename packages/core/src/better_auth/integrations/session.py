"""Shared session-resolution helpers for framework integrations.

The framework integrations (FastAPI, Starlette, Django, ...) all need to take a
request-like object, pull the better-auth session cookie, verify it, and load
the session row from the adapter. This module centralises that logic so each
integration is a thin adapter over the same core flow.
"""

from __future__ import annotations

from typing import Protocol

from better_auth.auth import BetterAuth
from better_auth.cookies import verify
from better_auth.types.adapter import Where
from better_auth.types.context import Session


class _CookieCarrier(Protocol):
    """Anything that exposes a `.cookies` mapping (Starlette/FastAPI Request).

    Kept narrow on purpose — we only need cookie lookup.
    """

    @property
    def cookies(self) -> dict[str, str]: ...  # pragma: no cover - protocol


SESSION_COOKIE_NAME = "better-auth.session_token"


async def resolve_session(
    auth: BetterAuth,
    cookie_value: str | None,
) -> Session | None:
    """Verify a raw cookie value and load the session row.

    Returns ``None`` for missing, malformed, or unknown cookies. This is the
    framework-agnostic core; integrations should call it with the cookie value
    pulled from their own request type.
    """
    if not cookie_value:
        return None
    token = verify(cookie_value, secret=auth.context.secret)
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


async def resolve_session_from_request(
    request: _CookieCarrier,
    auth: BetterAuth,
) -> Session | None:
    """Convenience wrapper for Starlette/FastAPI-style requests."""
    return await resolve_session(auth, request.cookies.get(SESSION_COOKIE_NAME))


def strip_base_path(scope: dict, base_path: str) -> dict:
    """Return a scope with ``base_path`` stripped from ``path`` (HTTP only).

    Mirrors what the FastAPI/Starlette mount wrappers do so we can also reuse
    this from the Django bridge. If ``scope`` is not HTTP, returned as-is.
    """
    if scope.get("type") != "http":
        return scope
    path = scope.get("path", "")
    if base_path and path.startswith(base_path):
        new = dict(scope)
        new["path"] = path[len(base_path):] or "/"
        return new
    return scope


__all__ = [
    "SESSION_COOKIE_NAME",
    "resolve_session",
    "resolve_session_from_request",
    "strip_base_path",
]
