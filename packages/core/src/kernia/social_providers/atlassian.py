"""Atlassian OAuth2 provider. Mirrors `reference/.../social-providers/atlassian.ts`."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from kernia.social_providers._base import OAuthProvider, OAuthUserProfile
from kernia.social_providers._helpers import make_provider


def _atlassian_profile(raw: Mapping[str, Any]) -> OAuthUserProfile:
    return OAuthUserProfile(
        id=str(raw["account_id"]),
        email=raw.get("email"),
        email_verified=bool(raw.get("email_verified", False)),
        name=raw.get("name") or raw.get("nickname"),
        image=raw.get("picture"),
        raw=raw,
    )


def atlassian(
    *,
    client_id: str,
    client_secret: str,
    scopes: tuple[str, ...] = ("read:jira-user", "offline_access"),
) -> OAuthProvider:
    return make_provider(
        id="atlassian",
        name="Atlassian",
        client_id=client_id,
        client_secret=client_secret,
        authorization_endpoint="https://auth.atlassian.com/authorize",
        token_endpoint="https://auth.atlassian.com/oauth/token",
        user_info_endpoint="https://api.atlassian.com/me",
        scopes=scopes,
        requires_pkce=True,
        extra_authorize_params={"audience": "api.atlassian.com"},
        profile_mapper=_atlassian_profile,
    )


__all__ = ["atlassian"]
