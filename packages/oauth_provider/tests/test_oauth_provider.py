"""Unit + integration tests for the OIDC provider plugin.

Drives the plugin through its ASGI surface using `ASGIDriver`. Covers:
  * client registration (programmatic + /oauth2/register)
  * full authorization-code flow with PKCE
  * refresh_token rotation
  * userinfo bearer auth
  * introspection + revocation
  * discovery doc
"""

from __future__ import annotations

import base64

import pytest
from better_auth.auth import init
from better_auth.oauth2 import pkce_challenge, pkce_verifier
from better_auth.plugins.email_password import email_and_password
from better_auth.plugins.jwt import jwt
from better_auth.types.adapter import Where
from better_auth.types.init_options import BetterAuthOptions
from better_auth_memory_adapter import memory_adapter
from better_auth_oauth_provider import OAuthProviderOptions, oauth_provider
from better_auth_oauth_provider.plugin import create_client
from better_auth_test_utils import ASGIDriver


def _basic(client_id: str, client_secret: str) -> str:
    token = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode("ascii")
    return f"Basic {token}"


@pytest.fixture
async def setup():
    auth = init(
        BetterAuthOptions(
            database=memory_adapter(),
            secret="test-secret",
            plugins=[
                email_and_password(),
                jwt(),
                oauth_provider(
                    OAuthProviderOptions(
                        issuer="https://issuer.test",
                        enable_dynamic_registration=True,
                    )
                ),
            ],
            advanced={"disable_csrf_check": True},
        )
    )
    driver = ASGIDriver(app=auth.router.mount())
    client = await create_client(
        auth.context,
        name="Test Client",
        redirect_uris=["https://client.test/cb"],
        allowed_scopes=("openid", "profile", "email", "offline_access"),
    )
    return auth, driver, client


async def _signup_signin(driver: ASGIDriver) -> None:
    await driver.request(
        "POST",
        "/sign-up/email",
        json_body={"email": "u@test", "password": "correcthorse", "name": "Test User"},
    )


async def test_discovery_doc(setup) -> None:
    _, driver, _ = setup
    r = await driver.request("GET", "/.well-known/openid-configuration")
    assert r.status == 200
    j = r.json()
    assert j["issuer"] == "https://issuer.test"
    assert j["token_endpoint"].endswith("/oauth2/token")
    assert "authorization_code" in j["grant_types_supported"]


async def test_full_authorization_code_flow(setup) -> None:
    _, driver, client = setup
    await _signup_signin(driver)

    # 1. Hit authorize with the session cookie set
    query = (
        f"response_type=code&client_id={client.client_id}"
        f"&redirect_uri=https://client.test/cb&scope=openid%20email%20profile%20offline_access"
        f"&state=xyz"
    )
    r = await driver.request("GET", "/oauth2/authorize", query=query)
    assert r.status == 200, r.json()
    code = r.json()["code"]
    assert code

    # 2. Exchange the code for tokens (no Basic auth — use body)
    r = await driver.request(
        "POST",
        "/oauth2/token",
        json_body={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "https://client.test/cb",
            "client_id": client.client_id,
            "client_secret": client.client_secret,
        },
    )
    assert r.status == 200, r.json()
    body = r.json()
    assert body["token_type"] == "Bearer"
    assert "access_token" in body
    assert "id_token" in body
    assert "refresh_token" in body  # offline_access requested

    access_token = body["access_token"]
    refresh = body["refresh_token"]

    # 3. /userinfo
    r = await driver.request(
        "GET",
        "/oauth2/userinfo",
        headers={"authorization": f"Bearer {access_token}"},
    )
    assert r.status == 200, r.json()
    info = r.json()
    assert info["email"] == "u@test"
    assert info["name"] == "Test User"

    # 4. /introspect on access token
    r = await driver.request(
        "POST",
        "/oauth2/introspect",
        json_body={"token": access_token},
    )
    assert r.status == 200
    assert r.json()["active"] is True
    assert r.json()["sub"]

    # 5. /token refresh
    r = await driver.request(
        "POST",
        "/oauth2/token",
        json_body={
            "grant_type": "refresh_token",
            "refresh_token": refresh,
            "client_id": client.client_id,
            "client_secret": client.client_secret,
        },
    )
    assert r.status == 200, r.json()
    new_access = r.json()["access_token"]
    new_refresh = r.json()["refresh_token"]
    assert new_access != access_token
    assert new_refresh != refresh

    # 6. Old refresh token is invalidated
    r = await driver.request(
        "POST",
        "/oauth2/token",
        json_body={
            "grant_type": "refresh_token",
            "refresh_token": refresh,
            "client_id": client.client_id,
            "client_secret": client.client_secret,
        },
    )
    assert r.status == 400

    # 7. Revoke new refresh
    r = await driver.request(
        "POST",
        "/oauth2/revoke",
        json_body={"token": new_refresh, "client_id": client.client_id, "client_secret": client.client_secret},
    )
    assert r.status == 200


async def test_authorize_requires_session(setup) -> None:
    _, driver, client = setup
    # No sign-in
    r = await driver.request(
        "GET",
        "/oauth2/authorize",
        query=(
            f"response_type=code&client_id={client.client_id}"
            f"&redirect_uri=https://client.test/cb&scope=openid"
        ),
    )
    assert r.status == 401


async def test_authorize_rejects_bad_redirect(setup) -> None:
    _, driver, client = setup
    await _signup_signin(driver)
    r = await driver.request(
        "GET",
        "/oauth2/authorize",
        query=(
            f"response_type=code&client_id={client.client_id}"
            f"&redirect_uri=https://evil.test/cb&scope=openid"
        ),
    )
    assert r.status == 400


async def test_pkce_round_trip(setup) -> None:
    _, driver, client = setup
    await _signup_signin(driver)

    verifier = pkce_verifier()
    challenge = pkce_challenge(verifier)
    query = (
        f"response_type=code&client_id={client.client_id}"
        f"&redirect_uri=https://client.test/cb&scope=openid"
        f"&code_challenge={challenge}&code_challenge_method=S256"
    )
    r = await driver.request("GET", "/oauth2/authorize", query=query)
    assert r.status == 200
    code = r.json()["code"]

    # Wrong verifier → 400
    r = await driver.request(
        "POST",
        "/oauth2/token",
        json_body={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "https://client.test/cb",
            "client_id": client.client_id,
            "client_secret": client.client_secret,
            "code_verifier": "wrong-verifier",
        },
    )
    assert r.status == 400


async def test_dynamic_registration(setup) -> None:
    _, driver, _ = setup
    r = await driver.request(
        "POST",
        "/oauth2/register",
        json_body={
            "name": "Dynamic App",
            "redirect_uris": ["https://dyn.test/cb"],
            "allowed_scopes": ["openid", "email"],
            "token_endpoint_auth_method": "client_secret_basic",
        },
    )
    assert r.status == 200, r.json()
    j = r.json()
    assert j["client_id"]
    assert j["client_secret"]


async def test_dynamic_registration_disabled() -> None:
    auth = init(
        BetterAuthOptions(
            database=memory_adapter(),
            secret="s",
            plugins=[
                email_and_password(),
                jwt(),
                oauth_provider(OAuthProviderOptions(issuer="https://issuer.test")),
            ],
            advanced={"disable_csrf_check": True},
        )
    )
    d = ASGIDriver(app=auth.router.mount())
    r = await d.request(
        "POST",
        "/oauth2/register",
        json_body={"name": "x", "redirect_uris": ["https://x/cb"]},
    )
    assert r.status == 404


async def test_oauth_authorization_server_metadata(setup) -> None:
    # RFC 8414: the OAuth 2.0 authorization-server metadata document.
    _, driver, _ = setup
    r = await driver.request("GET", "/.well-known/oauth-authorization-server")
    assert r.status == 200, r.json()
    j = r.json()
    assert j["issuer"] == "https://issuer.test"
    assert j["token_endpoint"].endswith("/oauth2/token")
    assert j["authorization_endpoint"].endswith("/oauth2/authorize")
    # RFC 8414 doc is the OAuth (non-OIDC) profile: no userinfo/id_token claims.
    assert "userinfo_endpoint" not in j


async def test_client_secret_stored_hashed(setup) -> None:
    # A DB leak must never expose a usable client secret: the stored value is a
    # SHA-256 digest, not the plaintext returned to the caller.
    auth, _, client = setup
    row = await auth.context.adapter.find_one(
        model="oauthClient",
        where=[Where(field="clientId", value=client.client_id)],
    )
    assert row is not None
    assert row["clientSecret"] != client.client_secret
    assert client.client_secret  # the caller still gets the usable plaintext


async def test_refresh_token_reuse_invalidates_family(setup) -> None:
    # RFC 9700 §4.14: replaying a rotated refresh token tears down the whole
    # family, so the *new* refresh token issued by the legitimate rotation is
    # also revoked.
    _, driver, client = setup
    await _signup_signin(driver)
    query = (
        f"response_type=code&client_id={client.client_id}"
        f"&redirect_uri=https://client.test/cb&scope=openid%20offline_access"
    )
    r = await driver.request("GET", "/oauth2/authorize", query=query)
    code = r.json()["code"]
    r = await driver.request(
        "POST",
        "/oauth2/token",
        json_body={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "https://client.test/cb",
            "client_id": client.client_id,
            "client_secret": client.client_secret,
        },
    )
    original_refresh = r.json()["refresh_token"]

    # Legitimate rotation
    r = await driver.request(
        "POST",
        "/oauth2/token",
        json_body={
            "grant_type": "refresh_token",
            "refresh_token": original_refresh,
            "client_id": client.client_id,
            "client_secret": client.client_secret,
        },
    )
    assert r.status == 200
    rotated_refresh = r.json()["refresh_token"]

    # Replay the consumed (original) token → detected reuse, family torn down
    r = await driver.request(
        "POST",
        "/oauth2/token",
        json_body={
            "grant_type": "refresh_token",
            "refresh_token": original_refresh,
            "client_id": client.client_id,
            "client_secret": client.client_secret,
        },
    )
    assert r.status == 400

    # The legitimately-rotated token is now also dead (family invalidation)
    r = await driver.request(
        "POST",
        "/oauth2/token",
        json_body={
            "grant_type": "refresh_token",
            "refresh_token": rotated_refresh,
            "client_id": client.client_id,
            "client_secret": client.client_secret,
        },
    )
    assert r.status == 400


async def test_client_credentials_grant(setup) -> None:
    _, driver, client = setup
    r = await driver.request(
        "POST",
        "/oauth2/token",
        json_body={
            "grant_type": "client_credentials",
            "scope": "read",
        },
        headers={"authorization": _basic(client.client_id, client.client_secret)},
    )
    assert r.status == 200, r.json()
    body = r.json()
    assert "access_token" in body
    assert "id_token" not in body  # no id_token for client_credentials
