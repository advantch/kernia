"""Paybin OAuth2 provider. Mirrors `reference/.../social-providers/paybin.ts`."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from better_auth.social_providers._base import OAuthProvider, OAuthUserProfile
from better_auth.social_providers._helpers import make_provider


def _paybin_profile(raw: Mapping[str, Any]) -> OAuthUserProfile:
    return OAuthUserProfile(
        id=str(raw.get("sub") or raw.get("id")),
        email=raw.get("email"),
        email_verified=bool(raw.get("email_verified", False)),
        name=raw.get("name"),
        image=raw.get("picture"),
        raw=raw,
    )


def paybin(
    *,
    client_id: str,
    client_secret: str,
    issuer: str = "https://idp.paybin.io",
    scopes: tuple[str, ...] = ("openid", "profile", "email"),
) -> OAuthProvider:
    base = issuer.rstrip("/")
    return make_provider(
        id="paybin",
        name="Paybin",
        client_id=client_id,
        client_secret=client_secret,
        authorization_endpoint=f"{base}/oauth2/authorize",
        token_endpoint=f"{base}/oauth2/token",
        user_info_endpoint=f"{base}/oauth2/userinfo",
        scopes=scopes,
        profile_mapper=_paybin_profile,
    )


__all__ = ["paybin"]
