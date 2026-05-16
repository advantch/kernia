"""Reddit OAuth2 provider. Mirrors `reference/.../social-providers/reddit.ts`."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from better_auth.social_providers._base import OAuthProvider, OAuthUserProfile
from better_auth.social_providers._helpers import make_provider


def _reddit_profile(raw: Mapping[str, Any]) -> OAuthUserProfile:
    return OAuthUserProfile(
        id=str(raw["id"]),
        email=None,  # Reddit does not expose email via this endpoint.
        email_verified=False,
        name=raw.get("name") or raw.get("subreddit", {}).get("display_name_prefixed"),
        image=(raw.get("icon_img") or "").split("?")[0] or None,
        raw=raw,
    )


def reddit(
    *,
    client_id: str,
    client_secret: str,
    scopes: tuple[str, ...] = ("identity",),
) -> OAuthProvider:
    return make_provider(
        id="reddit",
        name="Reddit",
        client_id=client_id,
        client_secret=client_secret,
        authorization_endpoint="https://www.reddit.com/api/v1/authorize",
        token_endpoint="https://www.reddit.com/api/v1/access_token",
        user_info_endpoint="https://oauth.reddit.com/api/v1/me",
        scopes=scopes,
        use_basic_auth=True,
        profile_mapper=_reddit_profile,
        extra_userinfo_headers={"user-agent": "better-auth"},
    )


__all__ = ["reddit"]
