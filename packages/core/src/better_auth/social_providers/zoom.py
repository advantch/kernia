"""Zoom OAuth2 provider. Mirrors `reference/.../social-providers/zoom.ts`."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from better_auth.social_providers._base import OAuthProvider, OAuthUserProfile
from better_auth.social_providers._helpers import make_provider


def _zoom_profile(raw: Mapping[str, Any]) -> OAuthUserProfile:
    return OAuthUserProfile(
        id=str(raw["id"]),
        email=raw.get("email"),
        email_verified=bool(raw.get("verified", False) == 1 or raw.get("email_verified", False)),
        name=(
            (raw.get("display_name"))
            or (f"{raw.get('first_name') or ''} {raw.get('last_name') or ''}".strip())
            or raw.get("email")
        ),
        image=raw.get("pic_url"),
        raw=raw,
    )


def zoom(
    *,
    client_id: str,
    client_secret: str,
    scopes: tuple[str, ...] = ("user:read",),
) -> OAuthProvider:
    return make_provider(
        id="zoom",
        name="Zoom",
        client_id=client_id,
        client_secret=client_secret,
        authorization_endpoint="https://zoom.us/oauth/authorize",
        token_endpoint="https://zoom.us/oauth/token",
        user_info_endpoint="https://api.zoom.us/v2/users/me",
        scopes=scopes,
        use_basic_auth=True,
        profile_mapper=_zoom_profile,
    )


__all__ = ["zoom"]
