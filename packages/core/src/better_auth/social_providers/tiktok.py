"""TikTok OAuth2 provider. Mirrors `reference/.../social-providers/tiktok.ts`."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import httpx

from better_auth.social_providers._base import OAuthProvider, OAuthUserProfile
from better_auth.social_providers._helpers import make_provider


_USER_INFO_URL = "https://open.tiktokapis.com/v2/user/info/?fields=open_id,union_id,avatar_url,display_name,username"


async def _tiktok_profile(tokens: Mapping[str, Any]) -> OAuthUserProfile:
    access_token = tokens.get("access_token")
    if not isinstance(access_token, str):
        raise ValueError("tiktok: token response missing access_token")
    async with httpx.AsyncClient(timeout=30.0) as client:
        r = await client.get(
            _USER_INFO_URL,
            headers={"authorization": f"Bearer {access_token}"},
        )
        r.raise_for_status()
        body = r.json()
    user = ((body or {}).get("data") or {}).get("user") or {}
    return OAuthUserProfile(
        id=str(user.get("open_id") or user.get("union_id") or ""),
        email=None,
        email_verified=False,
        name=user.get("display_name") or user.get("username"),
        image=user.get("avatar_url"),
        raw=body,
    )


def tiktok(
    *,
    client_id: str,
    client_secret: str,
    scopes: tuple[str, ...] = ("user.info.basic",),
) -> OAuthProvider:
    return make_provider(
        id="tiktok",
        name="TikTok",
        client_id=client_id,
        client_secret=client_secret,
        authorization_endpoint="https://www.tiktok.com/v2/auth/authorize/",
        token_endpoint="https://open.tiktokapis.com/v2/oauth/token/",
        user_info_endpoint=None,
        scopes=scopes,
        fetch_profile=_tiktok_profile,
    )


__all__ = ["tiktok"]
