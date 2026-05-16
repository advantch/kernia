"""Roblox OAuth2 provider. Mirrors `reference/.../social-providers/roblox.ts`."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from better_auth.social_providers._base import OAuthProvider, OAuthUserProfile
from better_auth.social_providers._helpers import make_provider


def _roblox_profile(raw: Mapping[str, Any]) -> OAuthUserProfile:
    return OAuthUserProfile(
        id=str(raw["sub"]),
        email=raw.get("email"),
        email_verified=bool(raw.get("email_verified", False)),
        name=raw.get("preferred_username") or raw.get("name"),
        image=raw.get("picture"),
        raw=raw,
    )


def roblox(
    *,
    client_id: str,
    client_secret: str,
    scopes: tuple[str, ...] = ("openid", "profile"),
) -> OAuthProvider:
    return make_provider(
        id="roblox",
        name="Roblox",
        client_id=client_id,
        client_secret=client_secret,
        authorization_endpoint="https://apis.roblox.com/oauth/v1/authorize",
        token_endpoint="https://apis.roblox.com/oauth/v1/token",
        user_info_endpoint="https://apis.roblox.com/oauth/v1/userinfo",
        scopes=scopes,
        profile_mapper=_roblox_profile,
    )


__all__ = ["roblox"]
