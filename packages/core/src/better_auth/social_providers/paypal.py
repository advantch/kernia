"""PayPal OAuth2 provider. Mirrors `reference/.../social-providers/paypal.ts`."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from better_auth.social_providers._base import OAuthProvider, OAuthUserProfile
from better_auth.social_providers._helpers import make_provider


def _paypal_profile(raw: Mapping[str, Any]) -> OAuthUserProfile:
    emails = raw.get("emails") or []
    primary_email = None
    if isinstance(emails, list) and emails:
        primary_email = next((e.get("value") for e in emails if e.get("primary")), None)
        primary_email = primary_email or emails[0].get("value")
    return OAuthUserProfile(
        id=str(raw.get("user_id") or raw.get("payer_id") or raw.get("sub")),
        email=primary_email or raw.get("email"),
        email_verified=bool(raw.get("verified_account", False)),
        name=raw.get("name"),
        image=raw.get("picture"),
        raw=raw,
    )


def paypal(
    *,
    client_id: str,
    client_secret: str,
    scopes: tuple[str, ...] = ("openid", "email", "profile"),
    sandbox: bool = False,
) -> OAuthProvider:
    if sandbox:
        auth_url = "https://www.sandbox.paypal.com/signin/authorize"
        token_url = "https://api-m.sandbox.paypal.com/v1/oauth2/token"
        userinfo_url = "https://api-m.sandbox.paypal.com/v1/identity/oauth2/userinfo"
    else:
        auth_url = "https://www.paypal.com/signin/authorize"
        token_url = "https://api-m.paypal.com/v1/oauth2/token"
        userinfo_url = "https://api-m.paypal.com/v1/identity/oauth2/userinfo"
    return make_provider(
        id="paypal",
        name="PayPal",
        client_id=client_id,
        client_secret=client_secret,
        authorization_endpoint=auth_url,
        token_endpoint=token_url,
        user_info_endpoint=userinfo_url,
        scopes=scopes,
        use_basic_auth=True,
        profile_mapper=_paypal_profile,
    )


__all__ = ["paypal"]
