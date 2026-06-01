"""Port of better-auth's upstream MCP test suite (vitest -> pytest).

Upstream source: ``reference/packages/better-auth/src/plugins/mcp/mcp.test.ts``
(better-auth v1.6.11). Each upstream ``it(...)`` is reproduced here with the
same name and the same assertion intent, against *this* repo's MCP story.

Architectural note (why some cases are skipped)
-----------------------------------------------
Upstream's ``mcp`` plugin embeds a full OAuth2/OIDC *authorization server*: it
delegates to the ``oidc-provider`` plugin and serves ``/mcp/register``,
``/mcp/authorize`` (GET, session -> code), ``/mcp/token`` (code/refresh ->
token), ``/mcp/userinfo``, the consent flow, PKCE, and the
``/.well-known/oauth-authorization-server`` discovery doc -- all mounted under
the ``/mcp/`` namespace.

In this Python port the responsibilities are split:

* The OAuth *issuer* endpoints live in the separate ``oauth_provider`` package
  at ``/oauth2/*`` (dynamic registration, code/refresh token exchange,
  userinfo, consent, PKCE, the RFC 8414 ``oauth-authorization-server`` doc).
* The ``mcp`` package here is a FastMCP-based *resource server*: it mints a
  resource-bound (RFC 8707) access token at ``POST /mcp/authorize`` and, on the
  FastMCP side, validates bearer tokens, serves the RFC 9728
  ``oauth-protected-resource`` doc, and answers anonymous MCP requests with a
  ``401 + WWW-Authenticate: Bearer resource_metadata=...`` challenge.

So the upstream cases that exercise ``/mcp/register`` / ``/mcp/token`` /
``/mcp/userinfo`` / the GET-``/mcp/authorize`` consent+PKCE browser flow do not
map onto endpoints owned by this package (they would require editing
``packages/core`` or ``packages/oauth_provider``). Those are ``skip``-ed with a
precise reason and their behavioral analogue lives in
``packages/oauth_provider/tests``. The resource-server cases (the
``withMCPAuth`` challenge, the protected-resource metadata, the
"no alg=none" security cases, and token accept/reject/scope/resource) are
ported as real FastMCP HTTP round-trips.
"""

from __future__ import annotations

import asyncio

import pytest
from kernia.auth import init
from kernia.plugins.email_password import email_and_password
from kernia.plugins.jwt import jwt
from kernia.plugins.jwt.plugin import issue_jwt
from kernia.plugins.mcp.plugin import MCPOptions, mcp
from kernia.types.init_options import KerniaOptions
from kernia_mcp import mcp_auth
from kernia_memory_adapter import memory_adapter
from fastmcp import FastMCP
from starlette.testclient import TestClient

BASE_URL = "https://mcp.test"
ISSUER = "https://issuer.test"


def _make_auth():
    return init(
        KerniaOptions(
            database=memory_adapter(),
            secret="test-secret",
            plugins=[
                email_and_password(),
                jwt(),
                mcp(MCPOptions(issuer=ISSUER)),
            ],
            advanced={"disable_csrf_check": True},
        )
    )


def _make_server(auth, *, required_scopes=None, authorization_servers=None):
    provider = mcp_auth(
        auth.context,
        base_url=BASE_URL,
        required_scopes=required_scopes,
        authorization_servers=authorization_servers or [ISSUER],
    )
    server = FastMCP("test-mcp", auth=provider)

    @server.tool
    def ping() -> str:  # a protected tool the auth gate guards
        return "pong"

    return server, provider


@pytest.fixture
def auth():
    return _make_auth()


async def _mint(auth, *, scope: str, resource: str | None) -> str:
    payload = {
        "sub": "user-1",
        "iss": ISSUER,
        "aud": resource or "mcp-client",
        "client_id": "mcp-client",
        "scope": scope,
    }
    if resource:
        payload["resource"] = resource
    token, _ = await issue_jwt(auth.context, payload=payload, ttl=3600)
    return token


def _mcp_call(client: TestClient, token: str | None):
    headers = {"Accept": "application/json, text/event-stream"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return client.post(
        "/mcp/",
        headers=headers,
        json={"jsonrpc": "2.0", "method": "tools/list", "id": 1},
    )


# ===========================================================================
# describe("mcp") — OAuth-issuer cases that live in `oauth_provider` here.
# ===========================================================================


@pytest.mark.skip(
    reason="upstream /mcp/register (RFC 7591 dynamic registration) is served by "
    "the oauth_provider package at /oauth2/register here, not by the mcp "
    "package; covered by packages/oauth_provider/tests."
)
def test_should_register_public_client_with_token_endpoint_auth_method_none():
    ...


@pytest.mark.skip(
    reason="upstream /mcp/register confidential-client path is oauth_provider's "
    "/oauth2/register; not owned by the mcp package."
)
def test_should_register_confidential_client_with_client_secret_basic():
    ...


@pytest.mark.skip(
    reason="upstream public-client PKCE browser flow drives GET /mcp/authorize + "
    "/mcp/token (authorization-code grant) which are oauth_provider's "
    "/oauth2/authorize + /oauth2/token here; mcp package only mints "
    "resource-bound tokens at POST /mcp/authorize."
)
def test_should_authenticate_public_client_with_pkce_only():
    ...


@pytest.mark.skip(
    reason="upstream /mcp/token rejects public clients missing code_verifier; the "
    "token endpoint is oauth_provider's /oauth2/token here."
)
def test_should_reject_public_client_without_code_verifier():
    ...


@pytest.mark.skip(
    reason="upstream confidential-client authorization-code flow uses GET "
    "/mcp/authorize + /mcp/token, owned by oauth_provider here."
)
def test_should_still_support_confidential_clients_in_mcp_context():
    ...


@pytest.mark.skip(
    reason="upstream it.skip — race-redemption regression deferred upstream; "
    "the consume primitive lives in oauth_provider here."
)
def test_rejects_concurrent_redemption_of_the_same_authorization_code():
    ...


@pytest.mark.skip(
    reason="upstream /.well-known/oauth-authorization-server (RFC 8414 AS metadata) "
    "is served by oauth_provider here, not the mcp package; the mcp package "
    "serves only the RFC 9728 protected-resource doc. See "
    "packages/oauth_provider/tests and the e2e alg=none case below."
)
def test_should_expose_oauth_discovery_metadata():
    ...


def test_should_expose_oauth_protected_resource_metadata(auth):
    """RFC 9728 protected-resource metadata, served by the FastMCP provider.

    Upstream asserts ``resource`` is the origin and ``authorization_servers``
    contains it. FastMCP serves this doc per-mount at
    ``/.well-known/oauth-protected-resource/mcp`` and binds ``resource`` to the
    mounted MCP path; we assert the resource is anchored at the base URL and the
    better-auth issuer is advertised as an authorization server.
    """
    _server, provider = _make_server(auth)
    server, _ = _server, provider
    app = server.http_app()
    with TestClient(app) as client:
        resp = client.get("/.well-known/oauth-protected-resource/mcp")
        assert resp.status_code == 200
        body = resp.json()
        assert body["resource"].startswith(BASE_URL)
        assert f"{ISSUER}/" in body["authorization_servers"]
        assert body["bearer_methods_supported"] == ["header"]


@pytest.mark.skip(
    reason="upstream refresh_token grant against /mcp/token; the token endpoint is "
    "oauth_provider's /oauth2/token here. Refresh-token client-auth security "
    "cases are covered in packages/oauth_provider/tests."
)
def test_should_handle_token_refresh_flow():
    ...


def test_should_return_user_info_from_userinfo_endpoint(auth):
    """Upstream asserts /mcp/userinfo returns null for an invalid bearer token.

    There is no /mcp/userinfo here (userinfo is oauth_provider's
    /oauth2/userinfo). The resource-server analogue: an MCP request bearing an
    invalid token is rejected (401) rather than yielding any user info.
    """
    server, _ = _make_server(auth)
    app = server.http_app()
    with TestClient(app) as client:
        resp = _mcp_call(client, "invalid-token")
        assert resp.status_code == 401


@pytest.mark.skip(
    reason="upstream ID-token issuance happens in the /mcp/token authorization-code "
    "grant (oauth_provider's /oauth2/token here); the mcp package mints a "
    "resource-bound access token, not an OIDC id_token."
)
def test_should_handle_id_token_requests():
    ...


@pytest.mark.skip(
    reason="upstream consent flow (prompt=consent -> /oauth/consent -> "
    "/oauth2/consent) is oauth_provider's; GET /mcp/authorize browser flow is "
    "not owned by the mcp package."
)
def test_should_handle_consent_flow_with_prompt_consent():
    ...


@pytest.mark.skip(
    reason="upstream prompt!=consent skip-consent path is oauth_provider's "
    "GET /oauth2/authorize behaviour."
)
def test_should_skip_consent_flow_when_prompt_is_not_consent():
    ...


@pytest.mark.skip(
    reason="upstream state=undefined guard is in the GET /mcp/authorize redirect "
    "(oauth_provider's /oauth2/authorize); POST /mcp/authorize here returns "
    "JSON, not a redirect."
)
def test_should_not_include_state_undefined_in_redirect_url():
    ...


# ===========================================================================
# describe("withMCPAuth") — owned by the mcp package (FastMCP auth gate).
# ===========================================================================


def test_withmcpauth_returns_401_with_correct_www_authenticate_header(auth):
    """Port of upstream "should return 401 ... right WWW-Authenticate header".

    Upstream's ``withMcpAuth`` wraps an MCP handler and answers an
    unauthenticated request with ``401`` and
    ``WWW-Authenticate: Bearer resource_metadata="<baseURL>/.../oauth-protected-resource"``.

    The Python equivalent is FastMCP's ``RequireAuthMiddleware``, installed by
    the ``RemoteAuthProvider`` that ``mcp_auth`` returns. We assert the same
    contract end-to-end: anonymous MCP request -> 401 with a ``Bearer`` challenge
    whose ``resource_metadata`` points at the protected-resource doc under the
    configured base URL.
    """
    server, _ = _make_server(auth)
    app = server.http_app()
    with TestClient(app) as client:
        resp = _mcp_call(client, token=None)
        assert resp.status_code == 401
        www = resp.headers.get("WWW-Authenticate")
        assert www is not None
        assert www.startswith("Bearer")
        assert (
            f'resource_metadata="{BASE_URL}/.well-known/oauth-protected-resource'
            in www
        )


# ===========================================================================
# Token validation (resource-server) — the verify_token / scope / RFC 8707
# resource-indicator semantics the mcp package owns end-to-end over HTTP.
# ===========================================================================


def test_valid_token_passes_the_auth_gate(auth):
    """A correctly signed, correctly-audienced token is not rejected by auth.

    (The MCP protocol then returns 400 for a session-less tools/list, but the
    auth gate has passed: no 401, no WWW-Authenticate challenge.)
    """
    server, _ = _make_server(auth)
    app = server.http_app()
    token = asyncio.run(_mint(auth, scope="mcp:read", resource=f"{BASE_URL}/"))
    with TestClient(app) as client:
        resp = _mcp_call(client, token)
        assert resp.status_code != 401
        assert resp.headers.get("WWW-Authenticate") is None


def test_forged_token_is_rejected(auth):
    server, _ = _make_server(auth)
    app = server.http_app()
    with TestClient(app) as client:
        resp = _mcp_call(client, "not-a-real-jwt")
        assert resp.status_code == 401


def test_wrong_resource_token_is_rejected(auth):
    """RFC 8707: a token minted for another resource must not be replayable."""
    server, _ = _make_server(auth)
    app = server.http_app()
    token = asyncio.run(
        _mint(auth, scope="mcp:read", resource="https://other.test/")
    )
    with TestClient(app) as client:
        resp = _mcp_call(client, token)
        assert resp.status_code == 401


def test_insufficient_scope_token_is_rejected(auth):
    server, _ = _make_server(auth, required_scopes=["mcp:write"])
    app = server.http_app()
    token = asyncio.run(_mint(auth, scope="mcp:read", resource=f"{BASE_URL}/"))
    with TestClient(app) as client:
        resp = _mcp_call(client, token)
        assert resp.status_code == 401


# ===========================================================================
# describe("mcp discovery metadata (security)")
# @see GHSA-9h47-pqcx-hjr4 — must never advertise alg=none.
# ===========================================================================


def test_protected_resource_doc_must_not_advertise_alg_none(auth):
    """Port of "/.well-known/oauth-protected-resource must not advertise alg=none"."""
    server, _ = _make_server(auth)
    app = server.http_app()
    with TestClient(app) as client:
        resp = client.get("/.well-known/oauth-protected-resource/mcp")
        assert resp.status_code == 200
        algs = resp.json().get("resource_signing_alg_values_supported", [])
        assert "none" not in algs
