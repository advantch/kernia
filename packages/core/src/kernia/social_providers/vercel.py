"""Vercel OAuth2 provider. Mirrors `reference/.../social-providers/vercel.ts`."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from kernia.social_providers._base import OAuthProvider, OAuthUserProfile
from kernia.social_providers._helpers import make_provider


def _vercel_profile(raw: Mapping[str, Any]) -> OAuthUserProfile:
    return OAuthUserProfile(
        id=str(raw.get("user_id") or raw.get("id")),
        email=raw.get("email"),
        email_verified=False,
        name=raw.get("name") or raw.get("username"),
        image=raw.get("avatar"),
        raw=raw,
    )


def vercel(
    *,
    client_id: str,
    client_secret: str,
    scopes: tuple[str, ...] = (),
) -> OAuthProvider:
    return make_provider(
        id="vercel",
        name="Vercel",
        client_id=client_id,
        client_secret=client_secret,
        authorization_endpoint="https://vercel.com/oauth/authorize",
        token_endpoint="https://api.vercel.com/login/oauth/token",
        user_info_endpoint="https://api.vercel.com/login/oauth/userinfo",
        scopes=scopes,
        profile_mapper=_vercel_profile,
    )


__all__ = ["vercel"]
