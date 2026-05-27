"""E2E test for the OAuth proxy plugin.

An SPA-style flow: the test drives the SPA's side by calling /oauth-proxy/authorize
to fetch the authorize URL, then directly simulates the IdP redirect back to
/oauth-proxy/callback with code+state. The plugin exchanges via MockIdP (an
in-process OIDC IdP served over `httpx.MockTransport`).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx
import pytest

from kernia.auth import init
from kernia.oauth2 import exchange_code, fetch_userinfo, verify_id_token
from kernia.plugins.oauth_proxy import OAuthProxyOptions, oauth_proxy
from kernia.social_providers._base import OAuthProvider, OAuthUserProfile
from kernia.types.init_options import KerniaOptions
from kernia_memory_adapter import memory_adapter
from kernia_test_utils import ASGIDriver
from kernia_test_utils.mock_idp import MockIdP


@dataclass
class _MockProvider:
    """Tiny `OAuthProvider` impl backed by a `MockIdP` over an httpx transport."""

    client_id: str
    http_client: httpx.AsyncClient
    issuer: str
    id: str = "mock"
    name: str = "Mock"
    scopes: tuple[str, ...] = ("openid", "email", "profile")

    async def authorize(
        self,
        *,
        redirect_uri: str,
        state: str,
        code_verifier: str | None,
        nonce: str | None,
    ) -> str:
        return f"{self.issuer}/authorize?state={state}&redirect_uri={redirect_uri}"

    async def validate_token(
        self,
        *,
        code: str,
        redirect_uri: str,
        code_verifier: str | None,
    ) -> Mapping[str, Any]:
        return await exchange_code(
            token_url=f"{self.issuer}/token",
            client_id=self.client_id,
            client_secret="server-secret-spa-cant-see",
            code=code,
            redirect_uri=redirect_uri,
            code_verifier=code_verifier,
            http_client=self.http_client,
        )

    async def user_profile(self, *, tokens: Mapping[str, Any]) -> OAuthUserProfile:
        id_token = tokens.get("id_token")
        if isinstance(id_token, str):
            claims = await verify_id_token(
                id_token=id_token,
                jwks_url=f"{self.issuer}/.well-known/jwks.json",
                audience=self.client_id,
                issuer=self.issuer,
                http_client=self.http_client,
            )
            return OAuthUserProfile(
                id=str(claims["sub"]),
                email=claims.get("email"),
                email_verified=bool(claims.get("email_verified", False)),
                name=claims.get("name"),
                image=claims.get("picture"),
                raw=dict(claims),
            )
        access = tokens.get("access_token")
        if not isinstance(access, str):
            raise ValueError("no usable token")
        claims = await fetch_userinfo(
            f"{self.issuer}/userinfo",
            access_token=access,
            http_client=self.http_client,
        )
        return OAuthUserProfile(
            id=str(claims["sub"]),
            email=claims.get("email"),
            email_verified=bool(claims.get("email_verified", False)),
            name=claims.get("name"),
            image=claims.get("picture"),
            raw=dict(claims),
        )


@pytest.fixture
def setup():
    idp = MockIdP(issuer="https://test-idp", audience="client-A")
    client = httpx.AsyncClient(transport=idp.mock_transport())
    provider = _MockProvider(
        client_id="client-A", http_client=client, issuer="https://test-idp"
    )
    auth = init(
        KerniaOptions(
            database=memory_adapter(),
            secret="test-secret",
            plugins=[
                oauth_proxy(
                    OAuthProxyOptions(
                        providers={"mock": provider},
                        redirect_uri="http://localhost:3000/api/auth/oauth-proxy/callback",
                        trusted_providers=("mock",),
                    )
                )
            ],
            advanced={"disable_csrf_check": True},
        )
    )
    return idp, ASGIDriver(app=auth.router.mount())


async def test_full_proxy_flow(setup) -> None:
    idp, driver = setup
    # 1. SPA asks the server for an authorize URL
    r = await driver.request(
        "POST",
        "/oauth-proxy/authorize",
        json_body={"provider": "mock", "callback_url": "/dashboard"},
    )
    assert r.status == 200, r.json()
    url = r.json()["url"]
    state = parse_qs(urlparse(url).query)["state"][0]

    # 2. Enqueue the user the IdP will hand back on /token exchange
    idp.create_user(sub="user-7", email="g@example.com", name="G")

    # 3. SPA's redirect URI gets hit — we simulate that by calling /callback directly
    r = await driver.request(
        "GET",
        "/oauth-proxy/callback",
        query=f"code=fakecode&state={state}",
    )
    assert r.status == 200, r.json()
    body = r.json()
    assert body["user"]["email"] == "g@example.com"
    assert body["callbackURL"] == "/dashboard"
    assert "better-auth.session_token" in driver.cookies


async def test_authorize_rejects_unknown_provider(setup) -> None:
    _, driver = setup
    r = await driver.request(
        "POST", "/oauth-proxy/authorize", json_body={"provider": "nope"}
    )
    assert r.status == 400


async def test_callback_rejects_bad_state(setup) -> None:
    _, driver = setup
    r = await driver.request(
        "GET", "/oauth-proxy/callback", query="code=c&state=notarealstate"
    )
    assert r.status == 400
