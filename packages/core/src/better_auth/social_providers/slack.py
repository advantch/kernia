"""Slack OAuth2 (OIDC) provider. Mirrors `reference/.../social-providers/slack.ts`."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from better_auth.social_providers._base import OAuthProvider, OAuthUserProfile
from better_auth.social_providers._helpers import make_provider


def _slack_profile(raw: Mapping[str, Any]) -> OAuthUserProfile:
    user_id = raw.get("https://slack.com/user_id") or raw.get("sub")
    return OAuthUserProfile(
        id=str(user_id),
        email=raw.get("email"),
        email_verified=bool(raw.get("email_verified", False)),
        name=raw.get("name"),
        image=raw.get("picture") or raw.get("https://slack.com/user_image_512"),
        raw=raw,
    )


def slack(
    *,
    client_id: str,
    client_secret: str,
    scopes: tuple[str, ...] = ("openid", "profile", "email"),
) -> OAuthProvider:
    return make_provider(
        id="slack",
        name="Slack",
        client_id=client_id,
        client_secret=client_secret,
        authorization_endpoint="https://slack.com/openid/connect/authorize",
        token_endpoint="https://slack.com/api/openid.connect.token",
        user_info_endpoint="https://slack.com/api/openid.connect.userInfo",
        scopes=scopes,
        profile_mapper=_slack_profile,
    )


__all__ = ["slack"]
