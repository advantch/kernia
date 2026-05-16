"""Cookie + session contract — mirrors `reference/packages/better-auth/src/cookies/`.

Better-auth uses a four-cookie model:

    1. session_token   — signed, contains the session id (or a JWE-wrapped session)
    2. session_data    — optional, cached session payload
    3. dont_remember   — set when the user opts out of "remember me"
    4. <provider>_state, <provider>_pkce, <provider>_nonce — per-flow ephemerals

This module defines the shapes only. Signing/verification implementations live in
`better_auth.cookies`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

SameSite = Literal["strict", "lax", "none"]


@dataclass(frozen=True, slots=True)
class CookieAttributes:
    """Attributes applied to a Set-Cookie header.

    Mirrors `CookieOptions` from cookies.ts. `max_age` is seconds; `expires` is an
    absolute unix timestamp (seconds). Use one or the other, not both.
    """

    path: str = "/"
    domain: str | None = None
    max_age: int | None = None
    expires: int | None = None
    http_only: bool = True
    secure: bool = True
    same_site: SameSite = "lax"
    partitioned: bool = False


@dataclass(frozen=True, slots=True)
class CookieDef:
    """A named cookie with its default attributes.

    The plugin system uses this to declare which cookies it owns and what attributes
    it expects. The core renders the actual Set-Cookie header from a `CookieDef` +
    a value.
    """

    name: str
    attributes: CookieAttributes


# Built-in cookie names — keep aligned with reference/packages/better-auth/src/cookies/index.ts
SESSION_TOKEN_COOKIE = "better-auth.session_token"
SESSION_DATA_COOKIE = "better-auth.session_data"
DONT_REMEMBER_COOKIE = "better-auth.dont_remember"
