"""Naver OAuth2 provider. Mirrors `reference/.../social-providers/naver.ts`."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from better_auth.social_providers._base import OAuthProvider, OAuthUserProfile
from better_auth.social_providers._helpers import make_provider


def _naver_profile(raw: Mapping[str, Any]) -> OAuthUserProfile:
    response = raw.get("response") or {}
    return OAuthUserProfile(
        id=str(response["id"]),
        email=response.get("email"),
        email_verified=False,
        name=response.get("name") or response.get("nickname"),
        image=response.get("profile_image"),
        raw=raw,
    )


def naver(
    *,
    client_id: str,
    client_secret: str,
    scopes: tuple[str, ...] = (),
) -> OAuthProvider:
    return make_provider(
        id="naver",
        name="Naver",
        client_id=client_id,
        client_secret=client_secret,
        authorization_endpoint="https://nid.naver.com/oauth2.0/authorize",
        token_endpoint="https://nid.naver.com/oauth2.0/token",
        user_info_endpoint="https://openapi.naver.com/v1/nid/me",
        scopes=scopes,
        profile_mapper=_naver_profile,
    )


__all__ = ["naver"]
