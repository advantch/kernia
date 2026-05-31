"""LinkedIn OAuth2 provider (OIDC). Mirrors `reference/.../social-providers/linkedin.ts`."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from kernia.social_providers._base import OAuthProvider, OAuthUserProfile
from kernia.social_providers._helpers import make_provider


def _linkedin_profile(raw: Mapping[str, Any]) -> OAuthUserProfile:
    return OAuthUserProfile(
        id=str(raw.get("sub") or raw.get("id") or ""),
        email=raw.get("email"),
        email_verified=bool(raw.get("email_verified", False)),
        name=raw.get("name"),
        image=raw.get("picture"),
        raw=raw,
    )


def linkedin(
    *,
    client_id: str,
    client_secret: str,
    scopes: tuple[str, ...] = ("openid", "profile", "email"),
) -> OAuthProvider:
    return make_provider(
        id="linkedin",
        name="LinkedIn",
        client_id=client_id,
        client_secret=client_secret,
        authorization_endpoint="https://www.linkedin.com/oauth/v2/authorization",
        token_endpoint="https://www.linkedin.com/oauth/v2/accessToken",
        user_info_endpoint="https://api.linkedin.com/v2/userinfo",
        scopes=scopes,
        profile_mapper=_linkedin_profile,
    )


__all__ = ["linkedin"]
