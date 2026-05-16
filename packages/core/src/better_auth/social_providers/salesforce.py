"""Salesforce OAuth2 provider. Mirrors `reference/.../social-providers/salesforce.ts`."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from better_auth.social_providers._base import OAuthProvider, OAuthUserProfile
from better_auth.social_providers._helpers import make_provider


def _sf_profile(raw: Mapping[str, Any]) -> OAuthUserProfile:
    photos = raw.get("photos") or {}
    image = photos.get("picture") if isinstance(photos, dict) else None
    return OAuthUserProfile(
        id=str(raw.get("user_id") or raw.get("sub")),
        email=raw.get("email"),
        email_verified=bool(raw.get("email_verified", False)),
        name=raw.get("display_name") or raw.get("name"),
        image=image,
        raw=raw,
    )


def salesforce(
    *,
    client_id: str,
    client_secret: str,
    scopes: tuple[str, ...] = ("openid", "profile", "email"),
    sandbox: bool = False,
) -> OAuthProvider:
    base = "https://test.salesforce.com" if sandbox else "https://login.salesforce.com"
    return make_provider(
        id="salesforce",
        name="Salesforce",
        client_id=client_id,
        client_secret=client_secret,
        authorization_endpoint=f"{base}/services/oauth2/authorize",
        token_endpoint=f"{base}/services/oauth2/token",
        user_info_endpoint=f"{base}/services/oauth2/userinfo",
        scopes=scopes,
        profile_mapper=_sf_profile,
    )


__all__ = ["salesforce"]
