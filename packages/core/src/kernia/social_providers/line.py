"""LINE OAuth2 provider. Mirrors `reference/.../social-providers/line.ts`."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from kernia.social_providers._base import OAuthProvider, OAuthUserProfile
from kernia.social_providers._helpers import make_provider


def _line_profile(raw: Mapping[str, Any]) -> OAuthUserProfile:
    return OAuthUserProfile(
        id=str(raw.get("sub") or raw.get("userId")),
        email=raw.get("email"),
        email_verified=False,
        name=raw.get("name"),
        image=raw.get("picture"),
        raw=raw,
    )


def line(
    *,
    client_id: str,
    client_secret: str,
    scopes: tuple[str, ...] = ("openid", "profile", "email"),
) -> OAuthProvider:
    return make_provider(
        id="line",
        name="LINE",
        client_id=client_id,
        client_secret=client_secret,
        authorization_endpoint="https://access.line.me/oauth2/v2.1/authorize",
        token_endpoint="https://api.line.me/oauth2/v2.1/token",
        user_info_endpoint="https://api.line.me/oauth2/v2.1/userinfo",
        scopes=scopes,
        profile_mapper=_line_profile,
    )


__all__ = ["line"]
