"""HubSpot helper for the generic OAuth plugin."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import httpx

from kernia.plugins.generic_oauth.config import GenericOAuthConfig


async def _get_user_info(tokens: Mapping[str, Any]) -> Mapping[str, Any] | None:
    access_token = tokens.get("access_token")
    if not isinstance(access_token, str):
        return None
    url = f"https://api.hubapi.com/oauth/v1/access-tokens/{access_token}"
    async with httpx.AsyncClient(timeout=30.0) as client:
        r = await client.get(url, headers={"content-type": "application/json"})
        if r.status_code != 200:
            return None
        raw = r.json()
    user_id = raw.get("user_id") or (raw.get("signed_access_token") or {}).get("userId")
    if not user_id:
        return None
    user_email = raw.get("user")
    return {
        "id": user_id,
        "name": user_email,
        "email": user_email,
        "image": None,
        "emailVerified": False,
    }


def hubspot(
    *,
    client_id: str,
    client_secret: str,
    scopes: tuple[str, ...] = ("oauth",),
    redirect_uri: str | None = None,
    pkce: bool = False,
) -> GenericOAuthConfig:
    return GenericOAuthConfig(
        provider_id="hubspot",
        client_id=client_id,
        client_secret=client_secret,
        scopes=scopes,
        redirect_uri=redirect_uri,
        authorization_url="https://app.hubspot.com/oauth/authorize",
        token_url="https://api.hubapi.com/oauth/v1/token",
        authentication="post",
        pkce=pkce,
        get_user_info=_get_user_info,
    )


__all__ = ["hubspot"]
