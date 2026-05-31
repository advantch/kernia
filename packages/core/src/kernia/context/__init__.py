"""Session helpers.

Mirrors `reference/packages/better-auth/src/context/`. Centralizes session creation
and revocation so plugins never construct `session` rows by hand.
"""

from __future__ import annotations

import json
import time
from typing import Any

from kernia.cookies import new_token, sign
from kernia.types.adapter import Where
from kernia.types.context import AuthContext, Session
from kernia.types.cookie import (
    DONT_REMEMBER_COOKIE,
    SESSION_DATA_COOKIE,
    SESSION_TOKEN_COOKIE,
    CookieAttributes,
)


def _cookie_secure(auth: AuthContext) -> bool:
    return auth.base_url.startswith("https")


def _apply_default_cookie_attributes(
    auth: AuthContext, attrs: CookieAttributes
) -> CookieAttributes:
    """Merge `advanced.defaultCookieAttributes` over a base set of attributes.

    Mirrors upstream's `...options.advanced?.defaultCookieAttributes` spread,
    which sits *before* per-cookie overrides — so it can set `partitioned`,
    `sameSite`, `secure`, `httpOnly`, `domain` but never the cookie's `maxAge`.
    Accepts both snake_case and camelCase keys."""
    import dataclasses

    advanced = getattr(auth.options, "advanced", None) or {}
    defaults = advanced.get("default_cookie_attributes")
    if defaults is None:
        defaults = advanced.get("defaultCookieAttributes")
    if not isinstance(defaults, dict) or not defaults:
        return attrs

    def pick(*keys: str) -> Any:
        for key in keys:
            if key in defaults:
                return defaults[key]
        return _UNSET

    changes: dict[str, Any] = {}
    for field_name, keys in (
        ("partitioned", ("partitioned",)),
        ("same_site", ("same_site", "sameSite")),
        ("secure", ("secure",)),
        ("http_only", ("http_only", "httpOnly")),
        ("domain", ("domain",)),
        ("path", ("path",)),
    ):
        value = pick(*keys)
        if value is not _UNSET:
            changes[field_name] = value
    return dataclasses.replace(attrs, **changes) if changes else attrs


_UNSET = object()


def session_token_cookie(
    auth: AuthContext, signed_token: str, *, remember_me: bool = True
) -> tuple[str, str, CookieAttributes]:
    """The `session_token` cookie. `Max-Age` is the session lifetime (`expires_in`)
    unless the session is non-persistent (`remember_me=False`)."""
    attrs = CookieAttributes(
        path="/",
        max_age=auth.options.session.expires_in if remember_me else None,
        http_only=True,
        secure=_cookie_secure(auth),
        same_site="lax",
    )
    return (SESSION_TOKEN_COOKIE, signed_token, _apply_default_cookie_attributes(auth, attrs))


def session_data_cookie(
    auth: AuthContext,
    *,
    session: Session,
    user: dict[str, Any] | None = None,
) -> tuple[str, str, CookieAttributes]:
    """The short-lived signed `session_data` cookie-cache.

    Mirrors upstream's cookie cache: a signed, base64url-encoded snapshot of the
    session (and user, when available) with its own short `Max-Age`
    (`cookie_cache_max_age`) — distinct from the long-lived `session_token`."""
    payload = {
        "session": {
            "session": {
                "id": session.id,
                "userId": session.user_id,
                "expiresAt": session.expires_at,
                "token": session.token,
            },
            "user": user,
        },
        "expiresAt": int(time.time()) + auth.options.session.cookie_cache_max_age,
    }
    encoded = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    value = sign(encoded, secret=auth.secret)
    attrs = CookieAttributes(
        path="/",
        max_age=auth.options.session.cookie_cache_max_age,
        http_only=True,
        secure=_cookie_secure(auth),
        same_site="lax",
    )
    return (SESSION_DATA_COOKIE, value, _apply_default_cookie_attributes(auth, attrs))


async def create_session(
    auth: AuthContext,
    *,
    user_id: str,
    ip_address: str | None = None,
    user_agent: str | None = None,
    remember_me: bool = True,
) -> tuple[Session, list[tuple[str, str, CookieAttributes]]]:
    """Persist a new session row and produce the cookies that should be set."""
    token = new_token()
    now = int(time.time())
    expires_at = now + auth.options.session.expires_in
    provider = auth.plugin_state.get("session_provider")
    if provider is not None and hasattr(provider, "create_session"):
        row = await provider.create_session(
            user_id=user_id,
            token=token,
            expires_at=expires_at,
            ip_address=ip_address,
            user_agent=user_agent,
        )
    else:
        row = await auth.adapter.create(
            model="session",
            data={
                "userId": user_id,
                "token": token,
                "expiresAt": expires_at,
                "ipAddress": ip_address,
                "userAgent": user_agent,
            },
        )
    session = Session(
        id=row["id"],
        user_id=row["userId"],
        expires_at=expires_at,
        token=token,
        ip_address=ip_address,
        user_agent=user_agent,
    )
    signed = sign(token, secret=auth.secret)
    cookies = [session_token_cookie(auth, signed, remember_me=remember_me)]
    if auth.options.session.cookie_cache_enabled:
        cookies.append(session_data_cookie(auth, session=session))
    if not remember_me:
        cookies.append((
            DONT_REMEMBER_COOKIE,
            "1",
            CookieAttributes(
                path="/",
                http_only=True,
                secure=_cookie_secure(auth),
                same_site="lax",
            ),
        ))
    return session, cookies


def should_refresh_session(auth: AuthContext, session: Session) -> bool:
    """True when the session is older than `update_age` and its cookie should be
    re-issued. Derived from `expires_at - expires_in + update_age` so we don't
    need a separate `updated_at` column (matches upstream's rolling refresh)."""
    opts = auth.options.session
    due_at = session.expires_at - opts.expires_in + opts.update_age
    return int(time.time()) >= due_at


def refresh_session_cookies(
    auth: AuthContext,
    *,
    session: Session,
    user: dict[str, Any] | None = None,
    remember_me: bool = True,
) -> list[tuple[str, str, CookieAttributes]]:
    """Cookies to re-emit on a get-session refresh: the `session_token` (with its
    full `expires_in` Max-Age preserved) and, when enabled, the `session_data`
    cache. Each is a separate Set-Cookie entry (never comma-joined)."""
    signed = sign(session.token, secret=auth.secret)
    cookies = [session_token_cookie(auth, signed, remember_me=remember_me)]
    if auth.options.session.cookie_cache_enabled:
        cookies.append(session_data_cookie(auth, session=session, user=user))
    return cookies


async def revoke_session(
    auth: AuthContext,
    *,
    token: str,
) -> list[tuple[str, str, CookieAttributes]]:
    """Delete the session row and emit cookie-clearing instructions."""
    provider = auth.plugin_state.get("session_provider")
    if provider is not None and hasattr(provider, "delete_session"):
        await provider.delete_session(token=token)
    else:
        await auth.adapter.delete_many(
            model="session",
            where=(Where(field="token", value=token),),
        )
    clear = CookieAttributes(path="/", max_age=0, http_only=True, secure=False, same_site="lax")
    return [
        (SESSION_TOKEN_COOKIE, "", clear),
        (DONT_REMEMBER_COOKIE, "", clear),
    ]


__all__ = [
    "create_session",
    "revoke_session",
    "refresh_session_cookies",
    "should_refresh_session",
    "session_data_cookie",
    "session_token_cookie",
]
