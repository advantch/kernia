"""Dropbox OAuth2 provider. Mirrors `reference/.../social-providers/dropbox.ts`.

The userinfo endpoint is a POST (not GET) — handled with a custom fetch.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import httpx

from kernia.social_providers._base import OAuthProvider, OAuthUserProfile
from kernia.social_providers._helpers import make_provider


async def _dropbox_profile(tokens: Mapping[str, Any]) -> OAuthUserProfile:
    access_token = tokens.get("access_token")
    if not isinstance(access_token, str):
        raise ValueError("dropbox: token response missing access_token")
    async with httpx.AsyncClient(timeout=30.0) as client:
        r = await client.post(
            "https://api.dropboxapi.com/2/users/get_current_account",
            headers={"authorization": f"Bearer {access_token}"},
        )
        r.raise_for_status()
        profile = r.json()
    name_obj = profile.get("name") or {}
    return OAuthUserProfile(
        id=str(profile["account_id"]),
        email=profile.get("email"),
        email_verified=bool(profile.get("email_verified", False)),
        name=name_obj.get("display_name") or name_obj.get("given_name"),
        image=profile.get("profile_photo_url"),
        raw=profile,
    )


def dropbox(
    *,
    client_id: str,
    client_secret: str,
    scopes: tuple[str, ...] = ("account_info.read",),
) -> OAuthProvider:
    return make_provider(
        id="dropbox",
        name="Dropbox",
        client_id=client_id,
        client_secret=client_secret,
        authorization_endpoint="https://www.dropbox.com/oauth2/authorize",
        token_endpoint="https://api.dropboxapi.com/oauth2/token",
        user_info_endpoint=None,
        scopes=scopes,
        fetch_profile=_dropbox_profile,
    )


__all__ = ["dropbox"]
