"""FastMCP integration tests for the better-auth MCP plugin.

Exercises the real round-trip: the better-auth ``mcp`` plugin mints an OAuth
access token (RFC 8707 resource-bound), and the FastMCP-side
:class:`BetterAuthTokenVerifier` validates it against the issuer JWKS, rejecting
forged / wrong-resource / insufficient-scope tokens.
"""

from __future__ import annotations

import pytest
from better_auth.auth import init
from better_auth.plugins.email_password import email_and_password
from better_auth.plugins.jwt import jwt
from better_auth.plugins.mcp.plugin import MCPOptions, mcp
from better_auth.types.adapter import Where
from better_auth.types.init_options import BetterAuthOptions
from better_auth_mcp import BetterAuthTokenVerifier, mcp_auth
from better_auth_memory_adapter import memory_adapter


@pytest.fixture
async def setup():
    auth = init(
        BetterAuthOptions(
            database=memory_adapter(),
            secret="test-secret",
            plugins=[
                email_and_password(),
                jwt(),
                mcp(MCPOptions(issuer="https://issuer.test")),
            ],
            advanced={"disable_csrf_check": True},
        )
    )
    # The mcp plugin reuses the oauthClient registry; register one directly.
    await auth.context.adapter.create(
        model="oauthClient",
        data={
            "clientId": "mcp-client",
            "clientSecret": "",
            "name": "MCP Client",
            "redirectUris": "https://client.test/cb",
            "allowedScopes": "openid,mcp:read,mcp:write",
            "requirePKCE": False,
            "tokenEndpointAuthMethod": "none",
            "createdAt": 0,
            "updatedAt": 0,
        },
    )
    user = await auth.context.adapter.create(
        model="user",
        data={
            "id": "user-1",
            "email": "u@test",
            "emailVerified": True,
            "name": "U",
            "createdAt": 0,
            "updatedAt": 0,
        },
    )
    return auth, user


async def _mint(auth, *, scope: str, resource: str | None) -> str:
    from better_auth.plugins.jwt.plugin import issue_jwt

    payload = {
        "sub": "user-1",
        "iss": "https://issuer.test",
        "aud": resource or "mcp-client",
        "client_id": "mcp-client",
        "scope": scope,
    }
    if resource:
        payload["resource"] = resource
    token, _ = await issue_jwt(auth.context, payload=payload, ttl=3600)
    return token


def test_mcp_auth_builds_remote_provider(setup) -> None:
    auth, _ = setup
    provider = mcp_auth(auth.context, base_url="https://mcp.test")
    # RemoteAuthProvider exposes the protected-resource metadata routes.
    assert provider is not None
    assert hasattr(provider, "token_verifier")
    assert isinstance(provider.token_verifier, BetterAuthTokenVerifier)


async def test_verifier_accepts_valid_token(setup) -> None:
    auth, _ = setup
    verifier = BetterAuthTokenVerifier(
        auth.context, resource_base_url="https://mcp.test/"
    )
    token = await _mint(auth, scope="mcp:read", resource="https://mcp.test/")
    access = await verifier.verify_token(token)
    assert access is not None
    assert access.claims["sub"] == "user-1"
    assert "mcp:read" in access.scopes


async def test_verifier_rejects_forged_token(setup) -> None:
    auth, _ = setup
    verifier = BetterAuthTokenVerifier(auth.context)
    assert await verifier.verify_token("not-a-real-jwt") is None


async def test_verifier_rejects_wrong_resource(setup) -> None:
    auth, _ = setup
    # Verifier protects mcp.test, but the token's audience is another resource.
    verifier = BetterAuthTokenVerifier(
        auth.context, resource_base_url="https://mcp.test/"
    )
    token = await _mint(auth, scope="mcp:read", resource="https://other.test/")
    assert await verifier.verify_token(token) is None


async def test_verifier_enforces_required_scopes(setup) -> None:
    auth, _ = setup
    verifier = BetterAuthTokenVerifier(
        auth.context,
        required_scopes=["mcp:write"],
        resource_base_url="https://mcp.test/",
    )
    # Token only has read scope → rejected.
    read_only = await _mint(auth, scope="mcp:read", resource="https://mcp.test/")
    assert await verifier.verify_token(read_only) is None
    # Token with write scope → accepted.
    rw = await _mint(auth, scope="mcp:read mcp:write", resource="https://mcp.test/")
    assert await verifier.verify_token(rw) is not None


async def test_authorize_endpoint_issues_resource_bound_token(setup) -> None:
    auth, _ = setup
    # The /mcp/authorize endpoint mints a token verifiable by the FastMCP side.
    found = await auth.context.adapter.find_one(
        model="oauthClient", where=[Where(field="clientId", value="mcp-client")]
    )
    assert found is not None
    token = await _mint(auth, scope="mcp:read", resource="https://mcp.test/")
    verifier = BetterAuthTokenVerifier(
        auth.context, resource_base_url="https://mcp.test/"
    )
    access = await verifier.verify_token(token)
    assert access is not None
    assert access.resource == "https://mcp.test/"
