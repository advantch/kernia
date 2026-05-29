"""Django middleware that hydrates ``request.better_auth_session``.

The middleware reads the session cookie, resolves it through the better-auth
core, and attaches the result (which may be ``None``) under a dedicated
namespace so Django's own auth/session stack remains untouched.

Because Django middleware runs sync by default, we cross the async boundary
with :func:`asgiref.sync.async_to_sync`. That is a thread hop per request —
the same trade-off documented on :class:`BetterAuthView`.
"""

from __future__ import annotations

from typing import Any

from asgiref.sync import async_to_sync
from better_auth.auth import BetterAuth
from better_auth.integrations.session import (
    SESSION_COOKIE_NAME,
    resolve_session,
)
from django.http import HttpRequest
from django.utils.deprecation import MiddlewareMixin


class BetterAuthMiddleware(MiddlewareMixin):
    """Attach ``request.better_auth_session`` and ``request.better_auth_user``.

    The auth instance is sourced from ``settings.BETTER_AUTH`` (the user's
    own ``BetterAuth`` object). Falling back to a no-op if the setting isn't
    configured keeps the middleware importable from tests that don't wire it.
    """

    def process_request(self, request: HttpRequest) -> None:
        auth = self._auth_from_settings()
        request.better_auth_session = None  # type: ignore[attr-defined]
        request.better_auth_user = None  # type: ignore[attr-defined]
        if auth is None:
            return
        cookie = request.COOKIES.get(SESSION_COOKIE_NAME)
        if not cookie:
            return
        session = async_to_sync(resolve_session)(auth, cookie)
        if session is None:
            return
        request.better_auth_session = session  # type: ignore[attr-defined]
        # Lazily resolve the user only when asked; many requests just need the
        # session id. We expose a thin callable proxy via attribute access.
        request.better_auth_user = _UserAccessor(auth, session.user_id)  # type: ignore[attr-defined]

    @staticmethod
    def _auth_from_settings() -> BetterAuth | None:
        from django.conf import settings

        return getattr(settings, "BETTER_AUTH", None)


class _UserAccessor:
    """Lazy user lookup.

    ``request.better_auth_user`` is a callable that loads the user row on first
    access; we keep it lazy so the middleware only pays for the session lookup
    unless the view actually wants the user.
    """

    def __init__(self, auth: BetterAuth, user_id: str) -> None:
        self._auth = auth
        self._user_id = user_id
        self._cached: dict[str, Any] | None = None

    @property
    def id(self) -> str:
        return self._user_id

    def load(self) -> dict[str, Any] | None:
        if self._cached is None:
            from better_auth.types.adapter import Where

            self._cached = async_to_sync(self._auth.context.adapter.find_one)(
                model="user",
                where=(Where(field="id", value=self._user_id),),
            )
        return self._cached
