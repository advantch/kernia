"""Hugging Face OAuth2 provider. Mirrors `reference/.../social-providers/huggingface.ts`."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from better_auth.social_providers._base import OAuthProvider, OAuthUserProfile
from better_auth.social_providers._helpers import make_provider


def _hf_profile(raw: Mapping[str, Any]) -> OAuthUserProfile:
    return OAuthUserProfile(
        id=str(raw.get("sub") or raw.get("id")),
        email=raw.get("email"),
        email_verified=bool(raw.get("email_verified", False)),
        name=raw.get("name") or raw.get("preferred_username"),
        image=raw.get("picture") or raw.get("avatarUrl"),
        raw=raw,
    )


def huggingface(
    *,
    client_id: str,
    client_secret: str,
    scopes: tuple[str, ...] = ("openid", "profile", "email"),
) -> OAuthProvider:
    return make_provider(
        id="huggingface",
        name="Hugging Face",
        client_id=client_id,
        client_secret=client_secret,
        authorization_endpoint="https://huggingface.co/oauth/authorize",
        token_endpoint="https://huggingface.co/oauth/token",
        user_info_endpoint="https://huggingface.co/oauth/userinfo",
        scopes=scopes,
        profile_mapper=_hf_profile,
    )


__all__ = ["huggingface"]
