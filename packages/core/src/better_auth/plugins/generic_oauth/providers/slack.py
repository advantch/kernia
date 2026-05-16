"""Slack helper for the generic OAuth plugin."""

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
            "https://slack.com/api/openid.connect.userInfo",
            headers={"authorization": f"Bearer {access_token}"},
        )
        if r.status_code != 200:
            return None
        raw = r.json()
    return {
        "id": raw.get("https://slack.com/user_id") or raw.get("sub"),
        "name": raw.get("name"),
        "email": raw.get("email"),
        "image": raw.get("picture") or raw.get("https://slack.com/user_image_512"),
        "emailVerified": bool(raw.get("email_verified", False)),
    }


def slack(
    *,
    client_id: str,
    client_secret: str,
    scopes: tuple[str, ...] = ("openid", "profile", "email"),
    redirect_uri: str | None = None,
    pkce: bool = False,
) -> GenericOAuthConfig:
    return GenericOAuthConfig(
        provider_id="slack",
        client_id=client_id,
        client_secret=client_secret,
        scopes=scopes,
        redirect_uri=redirect_uri,
        authorization_url="https://slack.com/openid/connect/authorize",
        token_url="https://slack.com/api/openid.connect.token",
        user_info_url="https://slack.com/api/openid.connect.userInfo",
        pkce=pkce,
        get_user_info=_get_user_info,
    )


__all__ = ["slack"]
