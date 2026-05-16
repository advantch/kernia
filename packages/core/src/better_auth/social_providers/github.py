"""GitHub OAuth2 provider.

Mirrors `reference/packages/core/src/social-providers/github.ts`. GitHub is
*not* OIDC — it does not issue id_tokens. We fetch the profile from
`api.github.com/user` and merge primary email from `/user/emails`.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import httpx

from better_auth.social_providers._base import OAuthProvider, OAuthUserProfile
from better_auth.social_providers._helpers import make_provider


async def _github_profile(tokens: Mapping[str, Any]) -> OAuthUserProfile:
    access_token = tokens.get("access_token")
    if not isinstance(access_token, str):
        raise ValueError("github: token response missing access_token")
    headers = {
        "user-agent": "better-auth",
        "authorization": f"Bearer {access_token}",
        "accept": "application/json",
    }
    async with httpx.AsyncClient(timeout=30.0) as client:
        r = await client.get("https://api.github.com/user", headers=headers)
        r.raise_for_status()
        profile: dict[str, Any] = r.json()
        email = profile.get("email")
        email_verified = False
        if not email:
            emails_r = await client.get(
                "https://api.github.com/user/emails", headers=headers
            )
            if emails_r.status_code == 200:
                emails = emails_r.json()
                primary = next((e for e in emails if e.get("primary")), None) or (
                    emails[0] if emails else None
                )
                if primary:
                    email = primary.get("email")
                    email_verified = bool(primary.get("verified", False))
    return OAuthUserProfile(
        id=str(profile["id"]),
        email=email,
        email_verified=email_verified,
        name=profile.get("name") or profile.get("login") or "",
        image=profile.get("avatar_url"),
        raw=profile,
    )


def github(
    *,
    client_id: str,
    client_secret: str,
    scopes: tuple[str, ...] = ("read:user", "user:email"),
) -> OAuthProvider:
    """Construct a GitHub provider."""
    return make_provider(
        id="github",
        name="GitHub",
        client_id=client_id,
        client_secret=client_secret,
        authorization_endpoint="https://github.com/login/oauth/authorize",
        token_endpoint="https://github.com/login/oauth/access_token",
        user_info_endpoint=None,
        scopes=scopes,
        fetch_profile=_github_profile,
    )


__all__ = ["github"]
