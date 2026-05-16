"""Microsoft Entra ID helper for the generic OAuth plugin."""

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
            "https://graph.microsoft.com/oidc/userinfo",
            headers={"authorization": f"Bearer {access_token}"},
        )
        if r.status_code != 200:
            return None
        raw = r.json()
    name = raw.get("name") or " ".join(
        p for p in (raw.get("given_name"), raw.get("family_name")) if p
    ).strip() or None
    return {
        "id": raw.get("sub"),
        "name": name,
        "email": raw.get("email") or raw.get("preferred_username"),
        "image": raw.get("picture"),
        "emailVerified": bool(raw.get("email_verified", False)),
    }


def microsoft_entra_id(
    *,
    client_id: str,
    client_secret: str,
    tenant_id: str,
    scopes: tuple[str, ...] = ("openid", "profile", "email"),
    redirect_uri: str | None = None,
    pkce: bool = False,
    disable_implicit_sign_up: bool = False,
    disable_sign_up: bool = False,
    override_user_info: bool = False,
) -> GenericOAuthConfig:
    return GenericOAuthConfig(
        provider_id="microsoft-entra-id",
        client_id=client_id,
        client_secret=client_secret,
        scopes=scopes,
        redirect_uri=redirect_uri,
        authorization_url=(
            f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize"
        ),
        token_url=(
            f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
        ),
        user_info_url="https://graph.microsoft.com/oidc/userinfo",
        pkce=pkce,
        disable_implicit_sign_up=disable_implicit_sign_up,
        disable_sign_up=disable_sign_up,
        override_user_info=override_user_info,
        get_user_info=_get_user_info,
    )


__all__ = ["microsoft_entra_id"]
