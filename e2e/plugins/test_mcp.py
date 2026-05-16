"""E2E test for the MCP plugin.

Registers a client via the OIDC provider's helper, calls /mcp/authorize to obtain
an access token, then verifies the token via the plugin's `introspect_mcp_token`.
"""

from __future__ import annotations

import pytest
from authlib.jose import JsonWebKey, jwt as jose_jwt

from better_auth.auth import init
from better_auth.plugins.email_password import email_and_password
from better_auth.plugins.jwt import jwt
from better_auth.plugins.mcp import MCPOptions, mcp
from better_auth.plugins.mcp.plugin import introspect_mcp_token
from better_auth.types.init_options import BetterAuthOptions
from better_auth_memory_adapter import memory_adapter
from better_auth_oauth_provider import OAuthProviderOptions, oauth_provider
from better_auth_oauth_provider.plugin import create_client
from better_auth_test_utils import ASGIDriver


@pytest.fixture
async def setup():
    auth = init(
        BetterAuthOptions(
            database=memory_adapter(),
            secret="test-secret",
            plugins=[
                email_and_password(),
                jwt(),
                oauth_provider(OAuthProviderOptions(issuer="https://issuer.test")),
                mcp(MCPOptions(issuer="https://issuer.test")),
            ],
            advanced={"disable_csrf_check": True},
        )
    )
    driver = ASGIDriver(app=auth.router.mount())
    client = await create_client(
        auth.context,
        name="MCP Client",
        redirect_uris=["https://mcp.test/cb"],
        allowed_scopes=("openid", "profile", "email", "mcp:read", "mcp:write"),
        token_endpoint_auth_method="none",
    )
    # Sign up so we have a real user_id
    r = await driver.request(
        "POST",
        "/sign-up/email",
        json_body={"email": "mcp@test", "password": "correcthorse", "name": "MCP User"},
    )
    assert r.status == 200
    user_id = r.json()["user"]["id"]
    return auth, driver, client, user_id


async def test_mcp_authorize_returns_signed_token(setup) -> None:
    auth, driver, client, user_id = setup
    r = await driver.request(
        "POST",
        "/mcp/authorize",
        json_body={
            "client_id": client.client_id,
            "scope": "mcp:read mcp:write",
            "resource": "https://api.example/mcp",
        },
    )
    assert r.status == 200, r.json()
    body = r.json()
    assert body["token_type"] == "Bearer"
    assert body["scope"] == "mcp:read mcp:write"
    assert body["resource"] == "https://api.example/mcp"
    token = body["access_token"]

    # Introspect via plugin helper
    claims = await introspect_mcp_token(
        auth.context, token, expected_resource="https://api.example/mcp"
    )
    assert claims["sub"] == user_id
    assert claims["client_id"] == client.client_id
    assert claims["aud"] == "https://api.example/mcp"
    assert claims["iss"] == "https://issuer.test"


async def test_mcp_introspect_rejects_wrong_resource(setup) -> None:
    auth, driver, client, _ = setup
    r = await driver.request(
        "POST",
        "/mcp/authorize",
        json_body={
            "client_id": client.client_id,
            "scope": "mcp:read",
            "resource": "https://api.example/mcp",
        },
    )
    token = r.json()["access_token"]
    with pytest.raises(ValueError, match="resource mismatch"):
        await introspect_mcp_token(
            auth.context, token, expected_resource="https://different/mcp"
        )


async def test_mcp_well_known(setup) -> None:
    _, driver, _, _ = setup
    r = await driver.request("GET", "/.well-known/oauth-authorization-server")
    assert r.status == 200
    j = r.json()
    assert j["issuer"] == "https://issuer.test"
    assert j["authorization_endpoint"].endswith("/mcp/authorize")
    assert j["resource_indicators_supported"] is True


async def test_mcp_rejects_unknown_client(setup) -> None:
    _, driver, _, _ = setup
    r = await driver.request(
        "POST",
        "/mcp/authorize",
        json_body={"client_id": "not-real", "scope": "mcp:read"},
    )
    assert r.status == 400


async def test_mcp_rejects_disallowed_scope(setup) -> None:
    _, driver, client, _ = setup
    r = await driver.request(
        "POST",
        "/mcp/authorize",
        json_body={"client_id": client.client_id, "scope": "admin:everything"},
    )
    assert r.status == 400


async def test_mcp_authorize_requires_user(setup) -> None:
    _, _, client, _ = setup
    # Build a fresh driver with no session
    fresh_auth = init(
        BetterAuthOptions(
            database=memory_adapter(),
            secret="s",
            plugins=[
                email_and_password(),
                jwt(),
                oauth_provider(OAuthProviderOptions(issuer="https://issuer.test")),
                mcp(MCPOptions(issuer="https://issuer.test")),
            ],
            advanced={"disable_csrf_check": True},
        )
    )
    fresh_client = await create_client(
        fresh_auth.context,
        name="X",
        redirect_uris=["https://x"],
        allowed_scopes=("mcp:read",),
    )
    d = ASGIDriver(app=fresh_auth.router.mount())
    r = await d.request(
        "POST",
        "/mcp/authorize",
        json_body={"client_id": fresh_client.client_id, "scope": "mcp:read"},
    )
    assert r.status == 401
