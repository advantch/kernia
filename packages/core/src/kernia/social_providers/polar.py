"""Polar OAuth2 provider. Mirrors `reference/.../social-providers/polar.ts`."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from kernia.social_providers._base import OAuthProvider, OAuthUserProfile
from kernia.social_providers._helpers import make_provider


def _polar_profile(raw: Mapping[str, Any]) -> OAuthUserProfile:
    return OAuthUserProfile(
        id=str(raw.get("sub") or raw.get("id")),
        email=raw.get("email"),
        email_verified=bool(raw.get("email_verified", False)),
        name=raw.get("name"),
        image=raw.get("picture") or raw.get("avatar_url"),
        raw=raw,
    )


def polar(
    *,
    client_id: str,
    client_secret: str,
    scopes: tuple[str, ...] = ("openid", "profile", "email"),
) -> OAuthProvider:
    return make_provider(
        id="polar",
        name="Polar",
        client_id=client_id,
        client_secret=client_secret,
        authorization_endpoint="https://polar.sh/oauth2/authorize",
        token_endpoint="https://api.polar.sh/v1/oauth2/token",
        user_info_endpoint="https://api.polar.sh/v1/oauth2/userinfo",
        scopes=scopes,
        profile_mapper=_polar_profile,
    )


__all__ = ["polar"]
