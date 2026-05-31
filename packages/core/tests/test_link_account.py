"""Unit tests for kernia.oauth2.link_account."""

from __future__ import annotations

import pytest

from kernia.auth import init
from kernia.error import APIError
from kernia.oauth2.link_account import handle_oauth_user_info
from kernia.social_providers._base import OAuthUserProfile
from kernia.types.adapter import Where
from kernia.types.init_options import KerniaOptions
from kernia_memory_adapter import memory_adapter


def _profile(sub: str = "g-1", email: str = "alice@example.com", verified: bool = True) -> OAuthUserProfile:
    return OAuthUserProfile(
        id=sub,
        email=email,
        email_verified=verified,
        name="Alice",
        image=None,
        raw={},
    )


def _build_ctx():
    auth = init(KerniaOptions(database=memory_adapter(), secret="s"))
    return auth.context


async def test_creates_new_user_and_account_on_first_sign_in() -> None:
    ctx = _build_ctx()
    user, account = await handle_oauth_user_info(
        ctx,
        provider_id="google",
        profile=_profile(),
        tokens={"access_token": "a", "expires_in": 3600},
    )
    assert user["email"] == "alice@example.com"
    assert account["userId"] == user["id"]
    assert account["providerId"] == "google"
    assert account["accessToken"] == "a"


async def test_repeat_sign_in_returns_existing_account_with_refreshed_tokens() -> None:
    ctx = _build_ctx()
    await handle_oauth_user_info(
        ctx,
        provider_id="google",
        profile=_profile(),
        tokens={"access_token": "old"},
    )
    _, account = await handle_oauth_user_info(
        ctx,
        provider_id="google",
        profile=_profile(),
        tokens={"access_token": "new"},
    )
    assert account["accessToken"] == "new"
    # No duplicate user row
    users = await ctx.adapter.find_many(
        model="user", where=(Where(field="email", value="alice@example.com"),)
    )
    assert len(users) == 1


async def test_link_via_verified_email_when_provider_is_trusted() -> None:
    ctx = _build_ctx()
    # pre-existing user with a different OAuth account
    existing_user, _ = await handle_oauth_user_info(
        ctx,
        provider_id="github",
        profile=_profile(sub="gh-1"),
        tokens={},
        trusted_providers=("github", "google"),
    )
    user, account = await handle_oauth_user_info(
        ctx,
        provider_id="google",
        profile=_profile(sub="g-1"),
        tokens={"access_token": "x"},
        trusted_providers=("github", "google"),
    )
    assert user["id"] == existing_user["id"]
    assert account["providerId"] == "google"


async def test_does_not_link_via_email_when_provider_untrusted() -> None:
    ctx = _build_ctx()
    existing, _ = await handle_oauth_user_info(
        ctx,
        provider_id="github",
        profile=_profile(sub="gh-1"),
        tokens={},
        trusted_providers=("github",),
    )
    user, _ = await handle_oauth_user_info(
        ctx,
        provider_id="some-random",
        profile=_profile(sub="r-1"),
        tokens={},
        trusted_providers=("github",),
    )
    # New user, not linked
    assert user["id"] != existing["id"]


async def test_does_not_link_via_email_when_email_unverified() -> None:
    ctx = _build_ctx()
    existing, _ = await handle_oauth_user_info(
        ctx,
        provider_id="github",
        profile=_profile(sub="gh-1", verified=True),
        tokens={},
        trusted_providers=("github", "google"),
    )
    user, _ = await handle_oauth_user_info(
        ctx,
        provider_id="google",
        profile=_profile(sub="g-1", verified=False),
        tokens={},
        trusted_providers=("github", "google"),
    )
    assert user["id"] != existing["id"]


async def test_explicit_link_to_user_id() -> None:
    ctx = _build_ctx()
    existing, _ = await handle_oauth_user_info(
        ctx,
        provider_id="github",
        profile=_profile(sub="gh-1"),
        tokens={},
    )
    user, account = await handle_oauth_user_info(
        ctx,
        provider_id="google",
        profile=_profile(sub="g-1"),
        tokens={"access_token": "y"},
        link_to_user_id=existing["id"],
    )
    assert user["id"] == existing["id"]
    assert account["userId"] == existing["id"]


async def test_explicit_link_conflict_when_account_already_links_to_someone_else() -> None:
    ctx = _build_ctx()
    user_a, _ = await handle_oauth_user_info(
        ctx, provider_id="google", profile=_profile(sub="g-1"), tokens={}
    )
    user_b = await ctx.adapter.create(
        model="user", data={"email": "b@example.com", "emailVerified": True}
    )
    with pytest.raises(APIError) as exc_info:
        await handle_oauth_user_info(
            ctx,
            provider_id="google",
            profile=_profile(sub="g-1"),
            tokens={},
            link_to_user_id=user_b["id"],
        )
    assert exc_info.value.code == "ACCOUNT_ALREADY_LINKED"


async def test_disable_sign_up_raises_when_no_match() -> None:
    ctx = _build_ctx()
    with pytest.raises(APIError) as exc_info:
        await handle_oauth_user_info(
            ctx,
            provider_id="google",
            profile=_profile(),
            tokens={},
            disable_sign_up=True,
        )
    assert exc_info.value.code == "SIGNUP_DISABLED"


async def test_tokens_encrypted_when_option_set() -> None:
    from kernia.oauth2.encryption import is_encrypted

    auth = init(
        KerniaOptions(
            database=memory_adapter(),
            secret="cookie-secret",
            advanced={"encrypt_oauth_tokens": True},
        )
    )
    _, account = await handle_oauth_user_info(
        auth.context,
        provider_id="google",
        profile=_profile(),
        tokens={"access_token": "plain-token", "refresh_token": "plain-refresh"},
    )
    assert is_encrypted(account["accessToken"])
    assert is_encrypted(account["refreshToken"])
