"""Microsoft (Entra ID / Azure AD) OAuth2 provider.

Mirrors `reference/packages/core/src/social-providers/microsoft-entra-id.ts`.
The tenant is part of the URL — `common` (any account), `organizations`,
`consumers`, or a tenant GUID — so we resolve URLs at construction time.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from kernia.social_providers._base import OAuthProvider, OAuthUserProfile
from kernia.social_providers._helpers import make_provider


def _microsoft_profile(raw: Mapping[str, Any]) -> OAuthUserProfile:
    name = raw.get("name") or " ".join(
        part for part in (raw.get("given_name"), raw.get("family_name")) if part
    ).strip() or None
    email = raw.get("email") or raw.get("preferred_username")
    return OAuthUserProfile(
        id=str(raw["sub"]),
        email=email,
        email_verified=bool(raw.get("email_verified", False)),
        name=name,
        image=raw.get("picture"),
        raw=raw,
    )


def microsoft(
    *,
    client_id: str,
    client_secret: str,
    tenant_id: str = "common",
    scopes: tuple[str, ...] = ("openid", "profile", "email"),
) -> OAuthProvider:
    """Construct a Microsoft Entra ID provider.

    `tenant_id` may be a tenant GUID or one of "common", "organizations",
    "consumers".
    """
    authorization_endpoint = (
        f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize"
    )
    token_endpoint = (
        f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    )
    return make_provider(
        id="microsoft",
        name="Microsoft",
        client_id=client_id,
        client_secret=client_secret,
        authorization_endpoint=authorization_endpoint,
        token_endpoint=token_endpoint,
        user_info_endpoint="https://graph.microsoft.com/oidc/userinfo",
        scopes=scopes,
        profile_mapper=_microsoft_profile,
    )


__all__ = ["microsoft"]
