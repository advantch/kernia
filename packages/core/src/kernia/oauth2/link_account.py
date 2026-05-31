"""OAuth user-info → user/account resolution.

Mirrors `handleOAuthUserInfo` in
`reference/packages/better-auth/src/oauth2/link-account.ts`.

This is the single place where an OAuth callback's user profile becomes a user
row + an account row in our DB. The rules (matching better-auth):

  1. If there's already an `account` row for `(provider_id, account_id)` —
     return that account's user and refresh the tokens.
  2. If a user already exists with the same verified email AND the configured
     account-linking trust policy allows it — link the new account to the
     existing user.
  3. Otherwise — create a new user and a new account.
  4. If sign-up is disabled and step 3 would fire — raise UNABLE_TO_CREATE_USER.

The `link_to_user_id` parameter is the explicit-link path: a signed-in user
clicked "link my Slack account" — we attach the new account to *their* user
unconditionally (after sanity checks).
"""

from __future__ import annotations

import time
from collections.abc import Mapping
from typing import Any

from kernia.error import APIError
from kernia.oauth2.encryption import encrypt_token
from kernia.social_providers._base import OAuthUserProfile
from kernia.types.adapter import Where
from kernia.types.context import AuthContext


async def handle_oauth_user_info(
    auth: AuthContext,
    *,
    provider_id: str,
    profile: OAuthUserProfile,
    tokens: Mapping[str, Any],
    link_to_user_id: str | None = None,
    disable_sign_up: bool = False,
    trusted_providers: tuple[str, ...] = (),
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Resolve a user + account for an OAuth callback. Returns `(user, account)`.

    Args:
      auth: live AuthContext (adapter, options, secret)
      provider_id: e.g. "google", "github"
      profile: normalized profile from the provider
      tokens: raw token bundle (access_token, refresh_token, id_token, expires_in)
      link_to_user_id: if set, force-link to this user (the explicit-link path)
      disable_sign_up: if True, refuse to create a new user (existing-only)
      trusted_providers: providers whose email_verified=True is trusted for
        cross-account merging
    """
    now = int(time.time())
    encrypt_tokens = bool(auth.options.advanced.get("encrypt_oauth_tokens"))

    def _maybe_encrypt(s: str | None) -> str | None:
        if s is None:
            return None
        return encrypt_token(s, secret=auth.secret) if encrypt_tokens else s

    account_payload = {
        "providerId": provider_id,
        "accountId": profile.id,
        "accessToken": _maybe_encrypt(_as_str(tokens.get("access_token"))),
        "refreshToken": _maybe_encrypt(_as_str(tokens.get("refresh_token"))),
        "idToken": _as_str(tokens.get("id_token")),
        "accessTokenExpiresAt": _expires_at(tokens, now),
        "scope": _as_str(tokens.get("scope")),
        "updatedAt": now,
    }

    # --- 1. existing account for (provider, accountId)?
    existing_account = await auth.adapter.find_one(
        model="account",
        where=(
            Where(field="providerId", value=provider_id),
            Where(field="accountId", value=profile.id),
        ),
    )
    if existing_account is not None:
        user = await auth.adapter.find_one(
            model="user",
            where=(Where(field="id", value=existing_account["userId"]),),
        )
        if user is None:
            raise APIError(500, "INTERNAL", message="orphan account row")
        if link_to_user_id and existing_account["userId"] != link_to_user_id:
            raise APIError(
                409,
                "ACCOUNT_ALREADY_LINKED",
                message="That OAuth account is already linked to a different user.",
            )
        updated = await auth.adapter.update(
            model="account",
            where=(Where(field="id", value=existing_account["id"]),),
            update=account_payload,
        )
        return user, updated or existing_account

    # --- 2. explicit link path
    if link_to_user_id:
        target = await auth.adapter.find_one(
            model="user",
            where=(Where(field="id", value=link_to_user_id),),
        )
        if target is None:
            raise APIError(404, "USER_NOT_FOUND")
        account = await auth.adapter.create(
            model="account",
            data={
                **account_payload,
                "userId": link_to_user_id,
                "createdAt": now,
            },
        )
        return target, account

    # --- 3. match by verified email (only for trusted providers)
    if profile.email and profile.email_verified and provider_id in trusted_providers:
        existing_user = await auth.adapter.find_one(
            model="user",
            where=(Where(field="email", value=profile.email),),
        )
        if existing_user is not None:
            account = await auth.adapter.create(
                model="account",
                data={
                    **account_payload,
                    "userId": existing_user["id"],
                    "createdAt": now,
                },
            )
            return existing_user, account

    # --- 4. create new user (unless sign-up is disabled)
    if disable_sign_up:
        raise APIError(403, "SIGNUP_DISABLED", message="Sign-up is disabled for this provider.")

    user = await auth.adapter.create(
        model="user",
        data={
            "email": profile.email or f"{profile.id}@{provider_id}.local",
            "emailVerified": bool(profile.email_verified),
            "name": profile.name,
            "image": profile.image,
            "createdAt": now,
            "updatedAt": now,
        },
    )
    account = await auth.adapter.create(
        model="account",
        data={
            **account_payload,
            "userId": user["id"],
            "createdAt": now,
        },
    )
    return user, account


def _as_str(v: Any) -> str | None:
    return v if isinstance(v, str) else None


def _expires_at(tokens: Mapping[str, Any], now: int) -> int | None:
    exp = tokens.get("expires_in")
    if isinstance(exp, int):
        return now + exp
    return None


__all__ = ["handle_oauth_user_info"]
