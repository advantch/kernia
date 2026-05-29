"""Shared fixtures + helpers for the ported oauth-provider test suite.

These mirror the upstream vitest harness (`getTestInstance` + `createAuthClient`)
adapted to the Python ASGI test driver. The upstream tests register a confidential
client via `auth.api.adminCreateOAuthClient` and drive a full browser-style flow;
here we register clients programmatically with `create_client` and drive the same
HTTP endpoints through `ASGIDriver`.
"""

from __future__ import annotations

import base64
import json

import pytest
from better_auth.auth import init
from better_auth.oauth2 import pkce_challenge, pkce_verifier
from better_auth.plugins.email_password import email_and_password
from better_auth.plugins.jwt import jwt
from better_auth.types.init_options import BetterAuthOptions
from better_auth_memory_adapter import memory_adapter
from better_auth_oauth_provider import OAuthProviderOptions, oauth_provider
from better_auth_oauth_provider.plugin import create_client
from better_auth_test_utils import ASGIDriver

ISSUER = "https://issuer.test"
REDIRECT_URI = "https://client.test/cb"
SCOPES = ("openid", "profile", "email", "offline_access")


def basic(client_id: str, client_secret: str) -> str:
    token = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode("ascii")
    return f"Basic {token}"


def decode_jwt_payload(token: str) -> dict:
    payload_b64 = token.split(".")[1]
    payload_b64 += "=" * (-len(payload_b64) % 4)
    return json.loads(base64.urlsafe_b64decode(payload_b64))


def make_auth(**oauth_kwargs):
    """Build an `init`ed auth instance with email/password + jwt + oauth-provider."""
    opts = {"issuer": ISSUER, "enable_dynamic_registration": True}
    opts.update(oauth_kwargs)
    return init(
        BetterAuthOptions(
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


async def signup(driver: ASGIDriver) -> None:
    await driver.request(
        "POST",
        "/sign-up/email",
        json_body={"email": "u@test", "password": "correcthorse", "name": "Test User"},
    )


async def authorize_code(
    driver: ASGIDriver,
    client,
    *,
    scope: str = "openid profile email offline_access",
    redirect_uri: str | None = None,
    use_pkce: bool = True,
) -> tuple[str, str | None]:
    """Run the authorize step, returning (code, code_verifier)."""
    redirect_uri = redirect_uri or client.redirect_uris[0]
    verifier = pkce_verifier() if use_pkce else None
    query = (
        f"response_type=code&client_id={client.client_id}"
        f"&redirect_uri={redirect_uri}&scope={scope.replace(' ', '%20')}&state=123"
    )
    if verifier:
        query += f"&code_challenge={pkce_challenge(verifier)}&code_challenge_method=S256"
    r = await driver.request("GET", "/oauth2/authorize", query=query)
    assert r.status == 200, r.json()
    return r.json()["code"], verifier


async def exchange_code(
    driver: ASGIDriver,
    client,
    code: str,
    verifier: str | None,
    *,
    redirect_uri: str | None = None,
    scope: str | None = None,
) -> dict:
    redirect_uri = redirect_uri or client.redirect_uris[0]
    body = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": client.client_id,
    }
    if client.client_secret:
        body["client_secret"] = client.client_secret
    if verifier:
        body["code_verifier"] = verifier
    if scope:
        body["scope"] = scope
    return await driver.request("POST", "/oauth2/token", json_body=body)


async def get_tokens(driver: ASGIDriver, client, *, scope: str | None = None) -> dict:
    s = scope or "openid profile email offline_access"
    code, verifier = await authorize_code(driver, client, scope=s)
    r = await exchange_code(driver, client, code, verifier, scope=s)
    assert r.status == 200, r.json()
    return r.json()


@pytest.fixture
async def confidential():
    """A signed-in user plus a confidential client (offline_access allowed)."""
    auth = make_auth()
    driver = ASGIDriver(app=auth.router.mount())
    await signup(driver)
    client = await create_client(
        auth.context,
        name="Test Client",
        redirect_uris=[REDIRECT_URI],
        allowed_scopes=SCOPES,
    )
    return auth, driver, client
