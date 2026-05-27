"""GitLab OAuth2 provider. Mirrors `reference/.../social-providers/gitlab.ts`."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from kernia.social_providers._base import OAuthProvider, OAuthUserProfile
from kernia.social_providers._helpers import make_provider


def _gitlab_profile(raw: Mapping[str, Any]) -> OAuthUserProfile:
    return OAuthUserProfile(
        id=str(raw["id"]) if raw.get("id") is not None else str(raw["sub"]),
        email=raw.get("email"),
        email_verified=bool(raw.get("email_verified", False)),
        name=raw.get("name") or raw.get("username"),
        image=raw.get("avatar_url") or raw.get("picture"),
        raw=raw,
    )


def gitlab(
    *,
    client_id: str,
    client_secret: str,
    issuer: str = "https://gitlab.com",
    scopes: tuple[str, ...] = ("read_user", "openid", "profile", "email"),
) -> OAuthProvider:
    base = issuer.rstrip("/")
    return make_provider(
        id="gitlab",
        name="GitLab",
        client_id=client_id,
        client_secret=client_secret,
        authorization_endpoint=f"{base}/oauth/authorize",
        token_endpoint=f"{base}/oauth/token",
        user_info_endpoint=f"{base}/oauth/userinfo",
        scopes=scopes,
        profile_mapper=_gitlab_profile,
    )


__all__ = ["gitlab"]
