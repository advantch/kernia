"""Linear OAuth2 provider. Mirrors `reference/.../social-providers/linear.ts`.

Linear's user profile is fetched via GraphQL — we do the GraphQL POST inline.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import httpx

from kernia.social_providers._base import OAuthProvider, OAuthUserProfile
from kernia.social_providers._helpers import make_provider


_QUERY = "query Me { viewer { id name email avatarUrl } }"


async def _linear_profile(tokens: Mapping[str, Any]) -> OAuthUserProfile:
    access_token = tokens.get("access_token")
    if not isinstance(access_token, str):
        raise ValueError("linear: token response missing access_token")
    async with httpx.AsyncClient(timeout=30.0) as client:
        r = await client.post(
            "https://api.linear.app/graphql",
            json={"query": _QUERY},
            headers={"authorization": f"Bearer {access_token}"},
        )
        r.raise_for_status()
        body = r.json()
    viewer = ((body or {}).get("data") or {}).get("viewer") or {}
    return OAuthUserProfile(
        id=str(viewer["id"]),
        email=viewer.get("email"),
        email_verified=False,
        name=viewer.get("name"),
        image=viewer.get("avatarUrl"),
        raw=body,
    )


def linear(
    *,
    client_id: str,
    client_secret: str,
    scopes: tuple[str, ...] = ("read",),
) -> OAuthProvider:
    return make_provider(
        id="linear",
        name="Linear",
        client_id=client_id,
        client_secret=client_secret,
        authorization_endpoint="https://linear.app/oauth/authorize",
        token_endpoint="https://api.linear.app/oauth/token",
        user_info_endpoint=None,
        scopes=scopes,
        fetch_profile=_linear_profile,
    )


__all__ = ["linear"]
