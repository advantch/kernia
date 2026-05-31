"""Discord OAuth2 provider. Mirrors `reference/.../social-providers/discord.ts`."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from kernia.social_providers._base import OAuthProvider, OAuthUserProfile
from kernia.social_providers._helpers import make_provider


def _discord_profile(raw: Mapping[str, Any]) -> OAuthUserProfile:
    avatar = raw.get("avatar")
    image = None
    if avatar:
        image = f"https://cdn.discordapp.com/avatars/{raw['id']}/{avatar}.png"
    return OAuthUserProfile(
        id=str(raw["id"]),
        email=raw.get("email"),
        email_verified=bool(raw.get("verified", False)),
        name=raw.get("global_name") or raw.get("username") or raw.get("display_name"),
        image=image,
        raw=raw,
    )


def discord(
    *,
    client_id: str,
    client_secret: str,
    scopes: tuple[str, ...] = ("identify", "email"),
) -> OAuthProvider:
    return make_provider(
        id="discord",
        name="Discord",
        client_id=client_id,
        client_secret=client_secret,
        authorization_endpoint="https://discord.com/api/oauth2/authorize",
        token_endpoint="https://discord.com/api/oauth2/token",
        user_info_endpoint="https://discord.com/api/users/@me",
        scopes=scopes,
        profile_mapper=_discord_profile,
    )


__all__ = ["discord"]
