"""Railway OAuth2 provider. Mirrors `reference/.../social-providers/railway.ts`."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from kernia.social_providers._base import OAuthProvider, OAuthUserProfile
from kernia.social_providers._helpers import make_provider


def _railway_profile(raw: Mapping[str, Any]) -> OAuthUserProfile:
    return OAuthUserProfile(
        id=str(raw.get("id")),
        email=raw.get("email"),
        email_verified=False,
        name=raw.get("name"),
        image=raw.get("avatar"),
        raw=raw,
    )


def railway(
    *,
    client_id: str,
    client_secret: str,
    scopes: tuple[str, ...] = ("read:user",),
) -> OAuthProvider:
    return make_provider(
        id="railway",
        name="Railway",
        client_id=client_id,
        client_secret=client_secret,
        authorization_endpoint="https://backboard.railway.com/oauth/auth",
        token_endpoint="https://backboard.railway.com/oauth/token",
        user_info_endpoint="https://backboard.railway.com/oauth/me",
        scopes=scopes,
        profile_mapper=_railway_profile,
    )


__all__ = ["railway"]
