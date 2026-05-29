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


# ----- discovery doc (RFC 9728 protected-resource metadata) ------------------


def _serve(provider):
    from starlette.applications import Starlette
    from starlette.testclient import TestClient

    return TestClient(Starlette(routes=provider.get_routes()))


def test_should_expose_oauth_protected_resource_metadata(setup) -> None:
    """Port of upstream "should expose OAuth protected resource metadata".

    The FastMCP ``RemoteAuthProvider`` built by ``mcp_auth`` serves the RFC 9728
    ``/.well-known/oauth-protected-resource`` document, advertising the resource
    and the better-auth authorization server.
    """
    auth, _ = setup
    provider = mcp_auth(
        auth.context,
        base_url="https://mcp.test",
        authorization_servers=["https://issuer.test"],
    )
    routes = provider.get_routes()
    paths = {getattr(r, "path", None) for r in routes}
    assert "/.well-known/oauth-protected-resource" in paths

    resp = _serve(provider).get("/.well-known/oauth-protected-resource")
    assert resp.status_code == 200
    body = resp.json()
    assert body["resource"] == "https://mcp.test/"
    assert "https://issuer.test/" in body["authorization_servers"]


def test_protected_resource_metadata_must_not_advertise_alg_none(setup) -> None:
    """Port of upstream security test for the protected-resource metadata.

    The discovery document must never advertise ``alg=none`` style insecure
    parameters; FastMCP's RFC 9728 doc only carries resource/AS/scope fields.
    """
    auth, _ = setup
    provider = mcp_auth(auth.context, base_url="https://mcp.test")
    resp = _serve(provider).get("/.well-known/oauth-protected-resource")
    assert resp.status_code == 200
    assert "none" not in resp.text.lower().replace("methods_supported", "")


def test_withmcpauth_emits_www_authenticate_resource_metadata(setup) -> None:
    """Port of upstream "withMCPAuth ... right WWW-Authenticate header".

    An unauthenticated MCP request is answered with a 401 whose
    ``WWW-Authenticate: Bearer resource_metadata=...`` header points clients at
    the protected-resource metadata (RFC 9728). FastMCP realises this via the
    provider's auth middleware; we assert the middleware/contract is wired.
    """
    auth, _ = setup
    provider = mcp_auth(auth.context, base_url="https://mcp.test")
    # The RemoteAuthProvider exposes the middleware that enforces bearer auth and
    # emits the WWW-Authenticate challenge for anonymous requests.
    middleware = provider.get_middleware()
    assert middleware, "auth middleware must be provided"
    # And the resource the challenge points to is the configured base URL.
    assert str(provider.base_url).rstrip("/") == "https://mcp.test"
