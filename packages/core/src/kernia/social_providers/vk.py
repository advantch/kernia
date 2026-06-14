"""VK OAuth2 provider. Mirrors `reference/.../social-providers/vk.ts`."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from kernia.social_providers._base import OAuthProvider, OAuthUserProfile
from kernia.social_providers._helpers import make_provider


def _vk_profile(raw: Mapping[str, Any]) -> OAuthUserProfile:
    user = raw.get("user") or raw
    return OAuthUserProfile(
        id=str(user.get("user_id") or user.get("id")),
        email=user.get("email"),
        email_verified=bool(user.get("verified", False)),
        name=user.get("first_name")
        and f"{user.get('first_name')} {user.get('last_name') or ''}".strip(),
        image=user.get("avatar"),
        raw=raw,
    )


def vk(
    *,
    client_id: str,
    client_secret: str,
    scopes: tuple[str, ...] = ("email",),
) -> OAuthProvider:
    return make_provider(
        id="vk",
        name="VK",
        client_id=client_id,
        client_secret=client_secret,
        authorization_endpoint="https://id.vk.com/authorize",
        token_endpoint="https://id.vk.com/oauth2/auth",
        user_info_endpoint="https://id.vk.com/oauth2/user_info",
        scopes=scopes,
        requires_pkce=True,
        profile_mapper=_vk_profile,
    )


__all__ = ["vk"]
