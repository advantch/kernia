"""Session helpers.

Mirrors `reference/packages/better-auth/src/context/`. Centralizes session creation
and revocation so plugins never construct `session` rows by hand.
"""

from __future__ import annotations

import time

from better_auth.cookies import new_token, sign
from better_auth.types.adapter import Where
from better_auth.types.context import AuthContext, Session
from better_auth.types.cookie import (
    DONT_REMEMBER_COOKIE,
    SESSION_TOKEN_COOKIE,
    CookieAttributes,
)


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
    attrs = CookieAttributes(
        path="/",
        max_age=auth.options.session.expires_in if remember_me else None,
        http_only=True,
        secure=auth.base_url.startswith("https"),
        same_site="lax",
    )
    cookies = [(SESSION_TOKEN_COOKIE, signed, attrs)]
    if not remember_me:
        cookies.append((
            DONT_REMEMBER_COOKIE,
            "1",
            CookieAttributes(path="/", http_only=True, secure=attrs.secure, same_site="lax"),
        ))
    return session, cookies


async def revoke_session(
    auth: AuthContext,
    *,
    token: str,
) -> list[tuple[str, str, CookieAttributes]]:
    """Delete the session row and emit cookie-clearing instructions."""
    await auth.adapter.delete_many(
        model="session",
        where=(Where(field="token", value=token),),
    )
    clear = CookieAttributes(path="/", max_age=0, http_only=True, secure=False, same_site="lax")
    return [
        (SESSION_TOKEN_COOKIE, "", clear),
        (DONT_REMEMBER_COOKIE, "", clear),
    ]


__all__ = ["create_session", "revoke_session"]
