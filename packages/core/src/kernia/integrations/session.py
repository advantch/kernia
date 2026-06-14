"""Shared session-resolution helpers for framework integrations.

The framework integrations (FastAPI, Starlette, Django, ...) all need to take a
request-like object, pull the Better Auth-compatible session cookie, verify it, and load
the session row from the adapter. This module centralises that logic so each
integration is a thin adapter over the same core flow.
"""

from __future__ import annotations

import time
from typing import Any, Protocol

from kernia.auth import Kernia
from kernia.cookies import verify
from kernia.types.adapter import Where
from kernia.types.context import Session


class _CookieCarrier(Protocol):
    """Anything that exposes a `.cookies` mapping (Starlette/FastAPI Request).

    Kept narrow on purpose — we only need cookie lookup.
    """

    @property
    def cookies(self) -> dict[str, str]: ...  # pragma: no cover - protocol


SESSION_COOKIE_NAME = "better-auth.session_token"


async def resolve_session(
    auth: Kernia,
    cookie_value: str | None,
) -> Session | None:
    """Verify a raw cookie value and load the session row.

    Returns ``None`` for missing, malformed, unknown, or **expired** cookies.
    An expired session is treated as absent — the stale row is deleted so it
    cannot be replayed — matching the router's `_attach_session` chokepoint and
    upstream Better Auth's `getSession`. This is the framework-agnostic core;
    integrations should call it with the cookie value pulled from their own
    request type.
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
    expires_at = int(row["expiresAt"])
    if expires_at < int(time.time()):
        await auth.context.adapter.delete_many(
            model="session",
            where=(Where(field="token", value=row["token"]),),
        )
        return None
    return Session(
        id=row["id"],
        user_id=row["userId"],
        expires_at=expires_at,
        token=row["token"],
        ip_address=row.get("ipAddress"),
        user_agent=row.get("userAgent"),
    )


async def resolve_session_from_request(
    request: _CookieCarrier,
    auth: Kernia,
) -> Session | None:
    """Convenience wrapper for Starlette/FastAPI-style requests."""
    return await resolve_session(auth, request.cookies.get(SESSION_COOKIE_NAME))


def strip_base_path(scope: dict[str, Any], base_path: str) -> dict[str, Any]:
    """Return a scope with ``base_path`` stripped from ``path`` (HTTP only).

    Mirrors what the FastAPI/Starlette mount wrappers do so we can also reuse
    this from the Django bridge. If ``scope`` is not HTTP, returned as-is.
    """
    if scope.get("type") != "http":
        return scope
    path = scope.get("path", "")
    if base_path and path.startswith(base_path):
        new = dict(scope)
        new["path"] = path[len(base_path) :] or "/"
        return new
    return scope


__all__ = [
    "SESSION_COOKIE_NAME",
    "resolve_session",
    "resolve_session_from_request",
    "strip_base_path",
]
