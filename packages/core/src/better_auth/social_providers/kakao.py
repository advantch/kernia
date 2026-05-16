"""Kakao OAuth2 provider. Mirrors `reference/.../social-providers/kakao.ts`."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from better_auth.social_providers._base import OAuthProvider, OAuthUserProfile
from better_auth.social_providers._helpers import make_provider


def _kakao_profile(raw: Mapping[str, Any]) -> OAuthUserProfile:
    account = raw.get("kakao_account") or {}
    profile = account.get("profile") or {}
    return OAuthUserProfile(
        id=str(raw["id"]),
        email=account.get("email"),
        email_verified=bool(account.get("is_email_verified", False)),
        name=profile.get("nickname"),
        image=profile.get("profile_image_url") or profile.get("thumbnail_image_url"),
        raw=raw,
    )


def kakao(
    *,
    client_id: str,
    client_secret: str,
    scopes: tuple[str, ...] = ("profile_nickname", "profile_image", "account_email"),
) -> OAuthProvider:
    return make_provider(
        id="kakao",
        name="Kakao",
        client_id=client_id,
        client_secret=client_secret,
        authorization_endpoint="https://kauth.kakao.com/oauth/authorize",
        token_endpoint="https://kauth.kakao.com/oauth/token",
        user_info_endpoint="https://kapi.kakao.com/v2/user/me",
        scopes=scopes,
        profile_mapper=_kakao_profile,
    )


__all__ = ["kakao"]
