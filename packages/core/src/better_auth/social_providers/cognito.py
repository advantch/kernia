"""Amazon Cognito OAuth2 provider. Mirrors `reference/.../social-providers/cognito.ts`."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from better_auth.social_providers._base import OAuthProvider, OAuthUserProfile
from better_auth.social_providers._helpers import make_provider


def _cognito_profile(raw: Mapping[str, Any]) -> OAuthUserProfile:
    return OAuthUserProfile(
        id=str(raw["sub"]),
        email=raw.get("email"),
        email_verified=bool(raw.get("email_verified", False)),
        name=raw.get("name") or raw.get("username"),
        image=raw.get("picture"),
        raw=raw,
    )


def cognito(
    *,
    client_id: str,
    client_secret: str,
    domain: str,
    scopes: tuple[str, ...] = ("openid", "profile", "email"),
) -> OAuthProvider:
    """Amazon Cognito.

    `domain` is the Cognito hosted-UI domain, e.g. ``my-app.auth.us-east-1.amazoncognito.com``.
    """
    clean = domain.replace("https://", "").replace("http://", "").rstrip("/")
    return make_provider(
        id="cognito",
        name="Cognito",
        client_id=client_id,
        client_secret=client_secret,
        authorization_endpoint=f"https://{clean}/oauth2/authorize",
        token_endpoint=f"https://{clean}/oauth2/token",
        user_info_endpoint=f"https://{clean}/oauth2/userinfo",
        scopes=scopes,
        profile_mapper=_cognito_profile,
    )


__all__ = ["cognito"]
