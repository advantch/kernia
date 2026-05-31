"""Spotify OAuth2 provider. Mirrors `reference/.../social-providers/spotify.ts`."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from kernia.social_providers._base import OAuthProvider, OAuthUserProfile
from kernia.social_providers._helpers import make_provider


def _spotify_profile(raw: Mapping[str, Any]) -> OAuthUserProfile:
    images = raw.get("images") or []
    image = images[0]["url"] if images and isinstance(images, list) else None
    return OAuthUserProfile(
        id=str(raw["id"]),
        email=raw.get("email"),
        email_verified=bool(raw.get("email_verified", False)),
        name=raw.get("display_name"),
        image=image,
        raw=raw,
    )


def spotify(
    *,
    client_id: str,
    client_secret: str,
    scopes: tuple[str, ...] = ("user-read-email", "user-read-private"),
) -> OAuthProvider:
    return make_provider(
        id="spotify",
        name="Spotify",
        client_id=client_id,
        client_secret=client_secret,
        authorization_endpoint="https://accounts.spotify.com/authorize",
        token_endpoint="https://accounts.spotify.com/api/token",
        user_info_endpoint="https://api.spotify.com/v1/me",
        scopes=scopes,
        profile_mapper=_spotify_profile,
    )


__all__ = ["spotify"]
