"""E2E tests for the OAuth proxy plugin.

Two flows are covered:

1. The upstream *passthrough* receiving endpoint, `GET /oauth-proxy-callback`.
   Ported from `reference/.../oauth-proxy/oauth-proxy.test.ts`'s "passthrough
   mode" describe block: we mint an encrypted profile payload with
   `symmetric_encrypt` (the same primitive the plugin uses) and assert the
   endpoint's decrypt / field-validation / freshness (maxAge) / user-creation /
   existing-user-linking / redirect behaviour.

2. A self-contained SPA helper flow (Python-only extension): /oauth-proxy/authorize
   + /oauth-proxy/callback driven against an in-process MockIdP.

Upstream cases NOT ported (and why): every test that drives the *sending* side of
the proxy — `client.signIn.social(...)` then `/callback/google?...` asserting the
provider URL's `state` got rewritten into an encrypted package and the production
callback 302s to `/oauth-proxy-callback?...&profile=...`. That design relies on
core wiring the Python port does not have within plugin scope: an encrypted (not
signed) OAuth `state`, a `before` hook seam on `/callback/:id` that can
short-circuit the core handler with a redirect, and `ctx.context.returned`
rewriting on `/sign-in/social`. The Python core signs its state and runs
`/callback/:provider` as a single inline handler, so those sender-side cases
require core changes that are out of scope here. The receiving half — which is
where all the payload validation / security logic lives — is ported in full
below.
"""

from __future__ import annotations

import json
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs, quote, urlparse

import httpx
import pytest
from kernia.auth import init
from kernia.oauth2 import exchange_code, fetch_userinfo, verify_id_token
from kernia.plugins.oauth_proxy import (
    OAuthProxyOptions,
    oauth_proxy,
    symmetric_decrypt,
    symmetric_encrypt,
)
from kernia.social_providers._base import OAuthUserProfile
from kernia.types.adapter import Where
from kernia.types.init_options import KerniaOptions
from kernia_memory_adapter import memory_adapter
from kernia_test_utils import ASGIDriver
from kernia_test_utils.mock_idp import MockIdP


def _header(r, name: str) -> str | None:
    for k, v in r.headers:
        if k.lower() == name.lower():
            return v
    return None


def _make_payload(
    *,
    email: str = "user@email.com",
    account_id: str = "123",
    provider_id: str = "google",
    callback_url: str = "/dashboard",
    timestamp: Any,
    **overrides: Any,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "userInfo": {
            "id": account_id,
            "email": email,
            "name": "Test User",
            "emailVerified": True,
        },
        "account": {
            "providerId": provider_id,
            "accountId": account_id,
            "accessToken": "test",
        },
        "state": "test-state",
        "callbackURL": callback_url,
        "timestamp": timestamp,
    }
    payload.update(overrides)
    return payload


# --------------------------------------------------------------------------------------
# Passthrough receiving endpoint: GET /oauth-proxy-callback
# --------------------------------------------------------------------------------------


def _passthrough_auth(**proxy_kwargs):
    secret = "test-secret"
    auth = init(
        KerniaOptions(
            database=memory_adapter(),
            secret=secret,
            base_url="http://preview.example.com",
            plugins=[oauth_proxy(OAuthProxyOptions(**proxy_kwargs))],
            advanced={"disable_csrf_check": True},
        )
    )
    return auth, ASGIDriver(app=auth.router.mount()), proxy_kwargs.get("secret") or secret


async def test_passthrough_creates_user_and_session() -> None:
    auth, driver, key = _passthrough_auth()
    payload = _make_payload(timestamp=time.time() * 1000)
    profile = symmetric_encrypt(key, json.dumps(payload))
    r = await driver.request(
        "GET",
        "/oauth-proxy-callback",
        query=f"callbackURL=%2Fdashboard&profile={quote(profile)}",
    )
    assert r.status == 302
    assert "/dashboard" in (_header(r, "location") or "")

    users = await auth.context.adapter.find_many(model="user", where=())
    assert len(users) == 1
    assert users[0]["email"] == "user@email.com"
    accounts = await auth.context.adapter.find_many(
        model="account", where=(Where(field="providerId", value="google"),)
    )
    assert len(accounts) == 1
    sessions = await auth.context.adapter.find_many(model="session", where=())
    assert len(sessions) == 1


async def test_passthrough_sets_session_cookie() -> None:
    _, driver, key = _passthrough_auth()
    payload = _make_payload(timestamp=time.time() * 1000)
    profile = symmetric_encrypt(key, json.dumps(payload))
    r = await driver.request(
        "GET", "/oauth-proxy-callback", query=f"profile={quote(profile)}"
    )
    assert r.status == 302
    assert "better-auth.session_token" in driver.cookies


async def test_reject_missing_profile() -> None:
    _, driver, _ = _passthrough_auth()
    r = await driver.request("GET", "/oauth-proxy-callback", query="callbackURL=%2Fx")
    assert r.status == 302
    assert "error=missing_profile" in (_header(r, "location") or "")


async def test_reject_invalid_profile() -> None:
    _, driver, _ = _passthrough_auth()
    # Not decryptable with the configured key.
    r = await driver.request(
        "GET", "/oauth-proxy-callback", query="profile=!!!not-base64!!!"
    )
    assert r.status == 302
    loc = _header(r, "location") or ""
    assert "error=invalid_profile" in loc or "error=invalid_payload" in loc


async def test_reject_expired_payload() -> None:
    _, driver, key = _passthrough_auth(max_age=60)
    payload = _make_payload(timestamp=time.time() * 1000 - 120000)  # 2 min ago
    profile = symmetric_encrypt(key, json.dumps(payload))
    r = await driver.request(
        "GET",
        "/oauth-proxy-callback",
        query=f"callbackURL=%2Fdashboard&profile={quote(profile)}",
    )
    assert r.status == 302
    assert "error=payload_expired" in (_header(r, "location") or "")


async def test_custom_max_age() -> None:
    _, driver, key = _passthrough_auth(max_age=5)
    payload = _make_payload(timestamp=time.time() * 1000 - 10000)  # 10s ago > 5s
    profile = symmetric_encrypt(key, json.dumps(payload))
    r = await driver.request(
        "GET",
        "/oauth-proxy-callback",
        query=f"callbackURL=%2Fdashboard&profile={quote(profile)}",
    )
    assert r.status == 302
    assert "error=payload_expired" in (_header(r, "location") or "")


async def test_reject_missing_timestamp() -> None:
    _, driver, key = _passthrough_auth()
    payload = _make_payload(timestamp=time.time() * 1000)
    del payload["timestamp"]
    profile = symmetric_encrypt(key, json.dumps(payload))
    r = await driver.request(
        "GET",
        "/oauth-proxy-callback",
        query=f"callbackURL=%2Fdashboard&profile={quote(profile)}",
    )
    assert r.status == 302
    assert "error=invalid_payload" in (_header(r, "location") or "")


async def test_reject_missing_user_info() -> None:
    _, driver, key = _passthrough_auth()
    payload = _make_payload(timestamp=time.time() * 1000)
    del payload["userInfo"]
    profile = symmetric_encrypt(key, json.dumps(payload))
    r = await driver.request(
        "GET",
        "/oauth-proxy-callback",
        query=f"callbackURL=%2Fdashboard&profile={quote(profile)}",
    )
    assert r.status == 302
    assert "error=invalid_payload" in (_header(r, "location") or "")


async def test_reject_non_numeric_timestamp() -> None:
    _, driver, key = _passthrough_auth()
    payload = _make_payload(timestamp="not-a-number")
    profile = symmetric_encrypt(key, json.dumps(payload))
    r = await driver.request(
        "GET",
        "/oauth-proxy-callback",
        query=f"callbackURL=%2Fdashboard&profile={quote(profile)}",
    )
    assert r.status == 302
    assert "error=invalid_payload" in (_header(r, "location") or "")


async def test_dedicated_secret_used_instead_of_global() -> None:
    dedicated = "oauth-proxy-dedicated-secret-key"
    auth, driver, key = _passthrough_auth(secret=dedicated)
    assert key == dedicated
    payload = _make_payload(timestamp=time.time() * 1000)
    encrypted = symmetric_encrypt(dedicated, json.dumps(payload))

    # Encrypted with the dedicated secret, NOT the global secret.
    assert "user@email.com" in symmetric_decrypt(dedicated, encrypted)
    # Decrypting with the wrong (global) secret must not recover the plaintext:
    # it either raises on decode or yields garbage that lacks the payload.
    try:
        wrong = symmetric_decrypt(auth.context.secret, encrypted)
    except Exception:
        wrong = ""
    assert "user@email.com" not in wrong

    r = await driver.request(
        "GET",
        "/oauth-proxy-callback",
        query=f"callbackURL=%2Fdashboard&profile={quote(encrypted)}",
    )
    assert r.status == 302
    assert "/dashboard" in (_header(r, "location") or "")
    users = await auth.context.adapter.find_many(model="user", where=())
    assert len(users) == 1
    assert users[0]["email"] == "user@email.com"


async def test_handle_existing_user_on_preview() -> None:
    auth, driver, key = _passthrough_auth(trusted_providers=("google",))
    now = int(time.time())
    await auth.context.adapter.create(
        model="user",
        data={
            "email": "user@email.com",
            "name": "Existing User",
            "emailVerified": True,
            "createdAt": now,
            "updatedAt": now,
        },
    )
    payload = _make_payload(
        timestamp=time.time() * 1000,
        account_id="google-user-id",
        userInfo={
            "id": "google-user-id",
            "email": "user@email.com",
            "name": "New Name",
            "emailVerified": True,
        },
    )
    profile = symmetric_encrypt(key, json.dumps(payload))
    r = await driver.request(
        "GET",
        "/oauth-proxy-callback",
        query=f"callbackURL=%2Fdashboard&profile={quote(profile)}",
    )
    assert r.status == 302
    assert "/dashboard" in (_header(r, "location") or "")

    # Still one user (account linked, not a new user).
    users = await auth.context.adapter.find_many(model="user", where=())
    assert len(users) == 1
    assert users[0]["email"] == "user@email.com"
    accounts = await auth.context.adapter.find_many(
        model="account", where=(Where(field="providerId", value="google"),)
    )
    assert len(accounts) == 1


# --------------------------------------------------------------------------------------
# SPA helper flow (Python-only extension)
# --------------------------------------------------------------------------------------


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
    r = await driver.request(
        "POST",
        "/oauth-proxy/authorize",
        json_body={"provider": "mock", "callback_url": "/dashboard"},
    )
    assert r.status == 200, r.json()
    url = r.json()["url"]
    state = parse_qs(urlparse(url).query)["state"][0]

    idp.create_user(sub="user-7", email="g@example.com", name="G")

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
