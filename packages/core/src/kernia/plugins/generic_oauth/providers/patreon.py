"""Patreon helper for the generic OAuth plugin."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import httpx

from kernia.plugins.generic_oauth.config import GenericOAuthConfig

_USER_URL = (
    "https://www.patreon.com/api/oauth2/v2/identity"
    "?fields[user]=email,full_name,image_url,is_email_verified"
)


async def _get_user_info(tokens: Mapping[str, Any]) -> Mapping[str, Any] | None:
    access_token = tokens.get("access_token")
    if not isinstance(access_token, str):
        return None
    async with httpx.AsyncClient(timeout=30.0) as client:
        r = await client.get(
            _USER_URL,
            headers={"authorization": f"Bearer {access_token}"},
        )
        if r.status_code != 200:
            return None
        body = r.json()
    data = (body or {}).get("data") or {}
    attrs = data.get("attributes") or {}
    return {
        "id": data.get("id"),
        "name": attrs.get("full_name"),
        "email": attrs.get("email"),
        "image": attrs.get("image_url"),
        "emailVerified": bool(attrs.get("is_email_verified", False)),
    }


def patreon(
    *,
    client_id: str,
    client_secret: str,
    scopes: tuple[str, ...] = ("identity[email]",),
    redirect_uri: str | None = None,
    pkce: bool = False,
) -> GenericOAuthConfig:
    return GenericOAuthConfig(
        provider_id="patreon",
        client_id=client_id,
        client_secret=client_secret,
        scopes=scopes,
        redirect_uri=redirect_uri,
        authorization_url="https://www.patreon.com/oauth2/authorize",
        token_url="https://www.patreon.com/api/oauth2/token",
        pkce=pkce,
        get_user_info=_get_user_info,
    )


__all__ = ["patreon"]
