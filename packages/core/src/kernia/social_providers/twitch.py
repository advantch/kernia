"""Twitch OAuth2 provider. Mirrors `reference/.../social-providers/twitch.ts`."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import httpx

from kernia.social_providers._base import OAuthProvider, OAuthUserProfile
from kernia.social_providers._helpers import make_provider


async def _twitch_fetch(tokens: Mapping[str, Any], client_id: str) -> OAuthUserProfile:
    access_token = tokens.get("access_token")
    if not isinstance(access_token, str):
        raise ValueError("twitch: token response missing access_token")
    async with httpx.AsyncClient(timeout=30.0) as client:
        r = await client.get(
            "https://api.twitch.tv/helix/users",
            headers={
                "authorization": f"Bearer {access_token}",
                "client-id": client_id,
            },
        )
        r.raise_for_status()
        body = r.json()
    data = (body.get("data") or [None])[0] or {}
    return OAuthUserProfile(
        id=str(data.get("id")),
        email=data.get("email"),
        email_verified=False,
        name=data.get("display_name") or data.get("login"),
        image=data.get("profile_image_url"),
        raw=body,
    )


def twitch(
    *,
    client_id: str,
    client_secret: str,
    scopes: tuple[str, ...] = ("user:read:email",),
) -> OAuthProvider:
    async def _profile(tokens: Mapping[str, Any]) -> OAuthUserProfile:
        return await _twitch_fetch(tokens, client_id)

    return make_provider(
        id="twitch",
        name="Twitch",
        client_id=client_id,
        client_secret=client_secret,
        authorization_endpoint="https://id.twitch.tv/oauth2/authorize",
        token_endpoint="https://id.twitch.tv/oauth2/token",
        user_info_endpoint=None,
        scopes=scopes,
        fetch_profile=_profile,
    )


__all__ = ["twitch"]
