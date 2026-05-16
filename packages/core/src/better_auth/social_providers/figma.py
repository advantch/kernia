"""Figma OAuth2 provider. Mirrors `reference/.../social-providers/figma.ts`.

Figma requires PKCE and uses HTTP Basic auth on the token endpoint.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from better_auth.social_providers._base import OAuthProvider, OAuthUserProfile
from better_auth.social_providers._helpers import make_provider


def _figma_profile(raw: Mapping[str, Any]) -> OAuthUserProfile:
    return OAuthUserProfile(
        id=str(raw["id"]),
        email=raw.get("email"),
        email_verified=False,
        name=raw.get("handle"),
        image=raw.get("img_url"),
        raw=raw,
    )


def figma(
    *,
    client_id: str,
    client_secret: str,
    scopes: tuple[str, ...] = ("current_user:read",),
) -> OAuthProvider:
    return make_provider(
        id="figma",
        name="Figma",
        client_id=client_id,
        client_secret=client_secret,
        authorization_endpoint="https://www.figma.com/oauth",
        token_endpoint="https://api.figma.com/v1/oauth/token",
        user_info_endpoint="https://api.figma.com/v1/me",
        scopes=scopes,
        requires_pkce=True,
        use_basic_auth=True,
        profile_mapper=_figma_profile,
    )


__all__ = ["figma"]
