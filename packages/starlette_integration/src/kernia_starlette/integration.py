"""Starlette mount + session helpers.

Mirrors the FastAPI integration; the heavy lifting is shared via
``kernia.integrations.session``. Starlette is ASGI-native so this is a
thin wrapper that mounts the auth router and exposes coroutine helpers any
endpoint or middleware can call with a Starlette ``Request``.
"""

from __future__ import annotations

from starlette.applications import Starlette
from starlette.exceptions import HTTPException
from starlette.requests import Request

from kernia.auth import Kernia
from kernia.integrations.session import (
    resolve_session_from_request,
    strip_base_path,
)
from kernia.types.context import Session


def mount_kernia(app: Starlette, auth: Kernia) -> None:
    """Mount the auth ASGI app at `auth.context.options.base_path`.

    Same base-path-stripping wrapper as the FastAPI integration; Starlette's
    ``Mount`` already trims the prefix from ``path``, but the inner router
    registers routes against the *full* base path so we keep parity with the
    FastAPI flow by re-asserting the strip ourselves.
    """
    base_path = auth.context.options.base_path.rstrip("/")
    inner = auth.router.mount()

    async def stripped(scope, receive, send):  # type: ignore[no-untyped-def]
        await inner(strip_base_path(scope, base_path), receive, send)

    app.mount(base_path, stripped)
    app.state.kernia = auth


async def get_session(request: Request) -> Session | None:
    """Returns the active session for the request, or ``None``."""
    auth: Kernia = request.app.state.kernia
    return await resolve_session_from_request(request, auth)


async def require_session(request: Request) -> Session:
    """Returns the active session or raises 401."""
    session = await get_session(request)
    if session is None:
        raise HTTPException(status_code=401, detail="UNAUTHORIZED")
    return session


__all__ = ["get_session", "mount_kernia", "require_session"]
