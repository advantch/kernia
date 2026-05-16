"""LINE helper for the generic OAuth plugin."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import httpx

from better_auth.plugins.generic_oauth.config import GenericOAuthConfig


async def _get_user_info(tokens: Mapping[str, Any]) -> Mapping[str, Any] | None:
    access_token = tokens.get("access_token")
    if not isinstance(access_token, str):
        return None
    async with httpx.AsyncClient(timeout=30.0) as client:
        r = await client.get(
            "https://api.line.me/oauth2/v2.1/userinfo",
            headers={"authorization": f"Bearer {access_token}"},
        )
        if r.status_code != 200:
            return None
        raw = r.json()
    return {
        "id": raw.get("sub"),
        "name": raw.get("name"),
        "email": raw.get("email"),
        "image": raw.get("picture"),
        "emailVerified": False,
    }


def line(
    *,
    client_id: str,
    client_secret: str,
    provider_id: str = "line",
    scopes: tuple[str, ...] = ("openid", "profile", "email"),
    redirect_uri: str | None = None,
    pkce: bool = False,
) -> GenericOAuthConfig:
    return GenericOAuthConfig(
        provider_id=provider_id,
        client_id=client_id,
        client_secret=client_secret,
        scopes=scopes,
        redirect_uri=redirect_uri,
        authorization_url="https://access.line.me/oauth2/v2.1/authorize",
        token_url="https://api.line.me/oauth2/v2.1/token",
        user_info_url="https://api.line.me/oauth2/v2.1/userinfo",
        pkce=pkce,
        get_user_info=_get_user_info,
    )


__all__ = ["line"]
