"""Gumroad helper for the generic OAuth plugin."""

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
            "https://api.gumroad.com/v2/user",
            headers={"authorization": f"Bearer {access_token}"},
        )
        if r.status_code != 200:
            return None
        body = r.json()
    if not body.get("success") or not body.get("user"):
        return None
    user = body["user"]
    return {
        "id": user.get("user_id"),
        "name": user.get("name"),
        "email": user.get("email"),
        "image": user.get("profile_url"),
        "emailVerified": False,
    }


def gumroad(
    *,
    client_id: str,
    client_secret: str,
    scopes: tuple[str, ...] = ("view_profile",),
    redirect_uri: str | None = None,
    pkce: bool = False,
) -> GenericOAuthConfig:
    return GenericOAuthConfig(
        provider_id="gumroad",
        client_id=client_id,
        client_secret=client_secret,
        scopes=scopes,
        redirect_uri=redirect_uri,
        authorization_url="https://gumroad.com/oauth/authorize",
        token_url="https://api.gumroad.com/oauth/token",
        pkce=pkce,
        get_user_info=_get_user_info,
    )


__all__ = ["gumroad"]
