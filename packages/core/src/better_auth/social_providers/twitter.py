"""Twitter / X OAuth2 provider. Mirrors `reference/.../social-providers/twitter.ts`."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from better_auth.social_providers._base import OAuthProvider, OAuthUserProfile
from better_auth.social_providers._helpers import make_provider


def _twitter_profile(raw: Mapping[str, Any]) -> OAuthUserProfile:
    data = raw.get("data") or raw
    return OAuthUserProfile(
        id=str(data["id"]),
        email=data.get("confirmed_email") or data.get("email"),
        email_verified=bool(data.get("verified", False)),
        name=data.get("name") or data.get("username"),
        image=data.get("profile_image_url"),
        raw=raw,
    )


def twitter(
    *,
    client_id: str,
    client_secret: str,
    scopes: tuple[str, ...] = ("users.read", "tweet.read", "offline.access"),
) -> OAuthProvider:
    return make_provider(
        id="twitter",
        name="Twitter",
        client_id=client_id,
        client_secret=client_secret,
        authorization_endpoint="https://x.com/i/oauth2/authorize",
        token_endpoint="https://api.x.com/2/oauth2/token",
        user_info_endpoint="https://api.x.com/2/users/me?user.fields=profile_image_url,confirmed_email",
        scopes=scopes,
        requires_pkce=True,
        use_basic_auth=True,
        profile_mapper=_twitter_profile,
    )


__all__ = ["twitter"]
