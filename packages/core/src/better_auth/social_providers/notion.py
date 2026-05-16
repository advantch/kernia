"""Notion OAuth2 provider. Mirrors `reference/.../social-providers/notion.ts`."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import httpx

from better_auth.social_providers._base import OAuthProvider, OAuthUserProfile
from better_auth.social_providers._helpers import make_provider


async def _notion_profile(tokens: Mapping[str, Any]) -> OAuthUserProfile:
    access_token = tokens.get("access_token")
    if not isinstance(access_token, str):
        raise ValueError("notion: token response missing access_token")
    async with httpx.AsyncClient(timeout=30.0) as client:
        r = await client.get(
            "https://api.notion.com/v1/users/me",
            headers={
                "authorization": f"Bearer {access_token}",
                "notion-version": "2022-06-28",
            },
        )
        r.raise_for_status()
        profile = r.json()
    bot = profile.get("bot") or {}
    owner = bot.get("owner") or {}
    user = owner.get("user") or {}
    person = user.get("person") or {}
    email = person.get("email")
    return OAuthUserProfile(
        id=str(profile.get("id")),
        email=email,
        email_verified=False,
        name=user.get("name") or profile.get("name"),
        image=user.get("avatar_url"),
        raw=profile,
    )


def notion(
    *,
    client_id: str,
    client_secret: str,
    scopes: tuple[str, ...] = (),
) -> OAuthProvider:
    return make_provider(
        id="notion",
        name="Notion",
        client_id=client_id,
        client_secret=client_secret,
        authorization_endpoint="https://api.notion.com/v1/oauth/authorize",
        token_endpoint="https://api.notion.com/v1/oauth/token",
        user_info_endpoint=None,
        scopes=scopes,
        use_basic_auth=True,
        fetch_profile=_notion_profile,
    )


__all__ = ["notion"]
