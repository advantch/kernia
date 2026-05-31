"""Kick OAuth2 provider. Mirrors `reference/.../social-providers/kick.ts`."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from kernia.social_providers._base import OAuthProvider, OAuthUserProfile
from kernia.social_providers._helpers import make_provider


def _kick_profile(raw: Mapping[str, Any]) -> OAuthUserProfile:
    data_list = raw.get("data") or []
    data = data_list[0] if data_list and isinstance(data_list, list) else raw
    return OAuthUserProfile(
        id=str(data.get("user_id") or data.get("id")),
        email=data.get("email"),
        email_verified=False,
        name=data.get("name") or data.get("username"),
        image=data.get("profile_picture"),
        raw=raw,
    )


def kick(
    *,
    client_id: str,
    client_secret: str,
    scopes: tuple[str, ...] = ("user:read",),
) -> OAuthProvider:
    return make_provider(
        id="kick",
        name="Kick",
        client_id=client_id,
        client_secret=client_secret,
        authorization_endpoint="https://id.kick.com/oauth/authorize",
        token_endpoint="https://id.kick.com/oauth/token",
        user_info_endpoint="https://api.kick.com/public/v1/users",
        scopes=scopes,
        requires_pkce=True,
        profile_mapper=_kick_profile,
    )


__all__ = ["kick"]
