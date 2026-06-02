"""E2E test for the MCP plugin.

Registers a client via the OIDC provider's helper, calls /mcp/authorize to obtain
an access token, then verifies the token via the plugin's `introspect_mcp_token`.
"""

from __future__ import annotations

import pytest
from kernia.auth import init
from kernia.plugins.email_password import email_and_password
from kernia.plugins.jwt import jwt
from kernia.plugins.mcp import MCPOptions, mcp
from kernia.plugins.mcp.plugin import introspect_mcp_token
from kernia.types.init_options import KerniaOptions
from kernia_memory_adapter import memory_adapter
from kernia_oauth_provider import OAuthProviderOptions, oauth_provider
from kernia_oauth_provider.plugin import create_client
from kernia_test_utils import ASGIDriver


@pytest.fixture
async def setup():
    auth = init(
        KerniaOptions(
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
    # RFC 9728 protected-resource metadata (the MCP server is a resource server;
    # the AS metadata lives on oauth_provider's oauth-authorization-server doc).
    r = await driver.request("GET", "/.well-known/oauth-protected-resource")
    assert r.status == 200
    j = r.json()
    assert j["resource"] == "https://issuer.test"
    assert j["authorization_servers"] == ["https://issuer.test"]
    assert j["authorization_endpoint"].endswith("/mcp/authorize")
    assert j["resource_indicators_supported"] is True


# Port of upstream describe("mcp discovery metadata (security)").
# @see https://github.com/better-auth/better-auth/security/advisories/GHSA-9h47-pqcx-hjr4
# The discovery documents must never advertise the insecure `alg=none`.


async def test_authorization_server_metadata_must_not_advertise_alg_none(setup) -> None:
    """Port of "/.well-known/oauth-authorization-server must not advertise alg=none".

    The RFC 8414 authorization-server metadata is served by the oauth_provider
    plugin in this repo (the mcp package is the resource server). Its
    ``id_token_signing_alg_values_supported`` must never contain ``none``.
    """
    _, driver, _, _ = setup
    r = await driver.request("GET", "/.well-known/oauth-authorization-server")
    assert r.status == 200
    algs = r.json().get("id_token_signing_alg_values_supported") or []
    assert "none" not in algs


async def test_protected_resource_metadata_must_not_advertise_alg_none(setup) -> None:
    """Port of "/.well-known/oauth-protected-resource must not advertise alg=none"."""
    _, driver, _, _ = setup
    r = await driver.request("GET", "/.well-known/oauth-protected-resource")
    assert r.status == 200
    algs = r.json().get("resource_signing_alg_values_supported") or []
    assert "none" not in algs


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
        KerniaOptions(
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
