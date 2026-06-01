"""Opaque (reference) access-token model parity.

Ports the upstream "opaque access_token" cases from
`reference/packages/oauth-provider/src/{token,introspect,userinfo,revoke}.test.ts`.

This port defaults to self-contained JWT access tokens; upstream defaults to
opaque reference tokens persisted in `oauthAccessToken` (minting a JWT only when
an audience/`resource` is present). Setting `jwt_access_token=False` selects the
upstream model, so the same introspection / userinfo / revocation behaviour can
be exercised against opaque tokens too. These tests configure that mode and assert
the token is *not* a JWT, that it round-trips through every consuming endpoint,
and that the `opaque_access_token_prefix` / `refresh_token_prefix` options surface
on the wire (mirroring upstream `prefix.opaqueAccessToken` / `prefix.refreshToken`).
"""

from __future__ import annotations

import pytest
from kernia.auth import init
from kernia.plugins.email_password import email_and_password
from kernia.plugins.jwt import jwt
from kernia.types.init_options import KerniaOptions
from kernia_memory_adapter import memory_adapter
from kernia_oauth_provider import OAuthProviderOptions, oauth_provider
from kernia_oauth_provider.plugin import create_client
from kernia_test_utils import ASGIDriver

from .conftest import (
    ISSUER,
    REDIRECT_URI,
    SCOPES,
    get_tokens,
    signup,
)


def _is_jwt(token: str) -> bool:
    """A compact JWS has exactly three dot-separated, non-empty segments."""
    parts = token.split(".")
    return len(parts) == 3 and all(parts)


async def _make_opaque(**oauth_kwargs):
    """A signed-in user + confidential client on an opaque-token issuer."""
    opts = {
        "issuer": ISSUER,
        "enable_dynamic_registration": True,
        "jwt_access_token": False,
    }
    opts.update(oauth_kwargs)
    auth = init(
        KerniaOptions(
            database=memory_adapter(),
            secret="test-secret-32-characters-long!!!",
            plugins=[
                email_and_password(),
                jwt(),
                oauth_provider(OAuthProviderOptions(**opts)),
            ],
            advanced={"disable_csrf_check": True},
        )
    )
    driver = ASGIDriver(app=auth.router.mount())
    await signup(driver)
    client = await create_client(
        auth.context,
        name="Test Client",
        redirect_uris=[REDIRECT_URI],
        allowed_scopes=SCOPES,
    )
    return auth, driver, client


@pytest.fixture
async def opaque():
    return await _make_opaque()


# ---------------------------------------------------------------------------
# Issuance
# ---------------------------------------------------------------------------


async def test_access_token_is_opaque_not_jwt(opaque) -> None:
    _, driver, client = opaque
    tokens = await get_tokens(driver, client)
    assert not _is_jwt(tokens["access_token"])
    # offline_access still mints a rotation-capable refresh token.
    assert "refresh_token" in tokens


async def test_opaque_access_token_prefix_client_credentials() -> None:
    _, driver, client = await _make_opaque(opaque_access_token_prefix="hello_")
    r = await driver.request(
        "POST",
        "/oauth2/token",
        json_body={
            "grant_type": "client_credentials",
            "client_id": client.client_id,
            "client_secret": client.client_secret,
            "scope": "read:profile",
        },
    )
    assert r.status == 200, r.json()
    assert r.json()["access_token"].startswith("hello_")


async def test_prefixes_on_code_and_refresh_flow() -> None:
    access_prefix = "hello__ac_"
    refresh_prefix = "hello_rt_"
    _, driver, client = await _make_opaque(
        opaque_access_token_prefix=access_prefix,
        refresh_token_prefix=refresh_prefix,
    )
    tokens = await get_tokens(driver, client)
    assert tokens["access_token"].startswith(access_prefix)
    assert tokens["refresh_token"].startswith(refresh_prefix)

    # Rotation preserves both prefixes on the freshly-minted pair.
    r = await driver.request(
        "POST",
        "/oauth2/token",
        json_body={
            "grant_type": "refresh_token",
            "refresh_token": tokens["refresh_token"],
            "client_id": client.client_id,
            "client_secret": client.client_secret,
        },
    )
    assert r.status == 200, r.json()
    refreshed = r.json()
    assert refreshed["access_token"].startswith(access_prefix)
    assert refreshed["refresh_token"].startswith(refresh_prefix)


# ---------------------------------------------------------------------------
# Introspection
# ---------------------------------------------------------------------------


async def _introspect(driver, client, token, hint=None):
    body = {
        "client_id": client.client_id,
        "client_secret": client.client_secret,
        "token": token,
    }
    if hint is not None:
        body["token_type_hint"] = hint
    return await driver.request("POST", "/oauth2/introspect", json_body=body)


async def test_introspect_opaque_access_token_active(opaque) -> None:
    _, driver, client = opaque
    tokens = await get_tokens(driver, client)
    r = await _introspect(driver, client, tokens["access_token"])
    assert r.status == 200, r.json()
    data = r.json()
    assert data["active"] is True
    assert data["client_id"] == client.client_id
    assert data["scope"] == "openid profile email offline_access"
    assert isinstance(data["sub"], str)
    assert data["iss"] == ISSUER
    assert data["token_type"] == "Bearer"


async def test_introspect_opaque_hint_access_token(opaque) -> None:
    _, driver, client = opaque
    tokens = await get_tokens(driver, client)
    r = await _introspect(driver, client, tokens["access_token"], "access_token")
    assert r.status == 200, r.json()
    assert r.json()["active"] is True


async def test_introspect_opaque_access_under_refresh_hint_inactive(opaque) -> None:
    _, driver, client = opaque
    tokens = await get_tokens(driver, client)
    r = await _introspect(driver, client, tokens["access_token"], "refresh_token")
    assert r.status == 200, r.json()
    assert not r.json()["active"]


async def test_introspect_unknown_opaque_token_inactive(opaque) -> None:
    _, driver, client = opaque
    r = await _introspect(driver, client, "not-a-real-token")
    assert r.status == 200, r.json()
    assert not r.json()["active"]


# ---------------------------------------------------------------------------
# Userinfo
# ---------------------------------------------------------------------------


async def test_userinfo_with_opaque_token(opaque) -> None:
    _, driver, client = opaque
    tokens = await get_tokens(driver, client)
    r = await driver.request(
        "GET",
        "/oauth2/userinfo",
        headers={"authorization": f"Bearer {tokens['access_token']}"},
    )
    assert r.status == 200, r.json()
    body = r.json()
    assert body["email"] == "u@test"
    assert isinstance(body["sub"], str)


async def test_userinfo_unknown_opaque_token_401(opaque) -> None:
    _, driver, client = opaque
    r = await driver.request(
        "GET",
        "/oauth2/userinfo",
        headers={"authorization": "Bearer not-a-real-token"},
    )
    assert r.status == 401


# ---------------------------------------------------------------------------
# Revocation
# ---------------------------------------------------------------------------


async def test_revoke_opaque_access_token(opaque) -> None:
    _, driver, client = opaque
    tokens = await get_tokens(driver, client)
    # Active before revocation.
    r = await _introspect(driver, client, tokens["access_token"])
    assert r.json()["active"] is True
    # Revoke it.
    r = await driver.request(
        "POST",
        "/oauth2/revoke",
        json_body={
            "client_id": client.client_id,
            "client_secret": client.client_secret,
            "token": tokens["access_token"],
        },
    )
    assert r.status == 200, r.json()
    # Now inactive, and userinfo rejects it.
    r = await _introspect(driver, client, tokens["access_token"])
    assert not r.json()["active"]
    r = await driver.request(
        "GET",
        "/oauth2/userinfo",
        headers={"authorization": f"Bearer {tokens['access_token']}"},
    )
    assert r.status == 401


async def test_revoke_with_opaque_access_token_prefix() -> None:
    # A prefixed opaque access token revokes (and goes inactive) just like the
    # unprefixed case — mirroring upstream "should pass with the correct
    # opaqueAccessTokenPrefix" in revoke.test.ts.
    _, driver, client = await _make_opaque(opaque_access_token_prefix="hello_")
    tokens = await get_tokens(driver, client)
    assert tokens["access_token"].startswith("hello_")
    r = await driver.request(
        "POST",
        "/oauth2/revoke",
        json_body={
            "client_id": client.client_id,
            "client_secret": client.client_secret,
            "token": tokens["access_token"],
            "token_type_hint": "access_token",
        },
    )
    assert r.status == 200, r.json()
    assert not (await _introspect(driver, client, tokens["access_token"])).json()[
        "active"
    ]


async def test_revoke_with_refresh_token_prefix() -> None:
    # A prefixed refresh token revokes and can no longer be exchanged — mirroring
    # upstream "should pass with the correct refreshTokenPrefix".
    _, driver, client = await _make_opaque(refresh_token_prefix="hello_rt_")
    tokens = await get_tokens(driver, client)
    assert tokens["refresh_token"].startswith("hello_rt_")
    r = await driver.request(
        "POST",
        "/oauth2/revoke",
        json_body={
            "client_id": client.client_id,
            "client_secret": client.client_secret,
            "token": tokens["refresh_token"],
            "token_type_hint": "refresh_token",
        },
    )
    assert r.status == 200, r.json()
    # The revoked refresh token can no longer be exchanged.
    r = await driver.request(
        "POST",
        "/oauth2/token",
        json_body={
            "grant_type": "refresh_token",
            "refresh_token": tokens["refresh_token"],
            "client_id": client.client_id,
            "client_secret": client.client_secret,
        },
    )
    assert r.status == 400
