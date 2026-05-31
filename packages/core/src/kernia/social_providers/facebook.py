"""Facebook OAuth2 provider. Mirrors `reference/.../social-providers/facebook.ts`."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from kernia.social_providers._base import OAuthProvider, OAuthUserProfile
from kernia.social_providers._helpers import make_provider


def _facebook_profile(raw: Mapping[str, Any]) -> OAuthUserProfile:
    pic = raw.get("picture")
    image = None
    if isinstance(pic, dict):
        image = pic.get("data", {}).get("url")
    return OAuthUserProfile(
        id=str(raw["id"]),
        email=raw.get("email"),
        email_verified=bool(raw.get("email_verified", False)),
        name=raw.get("name"),
        image=image,
        raw=raw,
    )


def facebook(
    *,
    client_id: str,
    client_secret: str,
    scopes: tuple[str, ...] = ("email", "public_profile"),
) -> OAuthProvider:
    return make_provider(
        id="facebook",
        name="Facebook",
        client_id=client_id,
        client_secret=client_secret,
        authorization_endpoint="https://www.facebook.com/v24.0/dialog/oauth",
        token_endpoint="https://graph.facebook.com/v24.0/oauth/access_token",
        user_info_endpoint="https://graph.facebook.com/me?fields=id,name,email,picture",
        scopes=scopes,
        profile_mapper=_facebook_profile,
    )


__all__ = ["facebook"]
