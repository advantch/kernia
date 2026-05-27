"""End-to-end OIDC flow against the in-process `MockIdP`.

Wires the `generic_oauth` plugin against a `MockIdP`, then drives the full
sign-in flow through `ASGIDriver`:

  1. GET  /oauth2/sign-in/<id>  → 302 to MockIdP's authorize endpoint
  2. POST /oauth2/callback/<id>  with the code → 302 to the configured
     callbackURL, with the session cookie attached
  3. The created user/account is observable via /list-accounts.

We patch the global `httpx.AsyncClient` constructor to inject the MockIdP
transport — that's the same pattern the existing OIDC tests use.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import httpx
import pytest

from kernia.auth import init
from kernia.plugins import email_and_password
from kernia.plugins.generic_oauth import GenericOAuthConfig, generic_oauth
from kernia.plugins.generic_oauth.routes import _DISCOVERY_CACHE
from kernia.types.adapter import Where
from kernia.types.init_options import KerniaOptions
from kernia_memory_adapter import memory_adapter
from kernia_test_utils import ASGIDriver
from kernia_test_utils.mock_idp import MockIdP


@pytest.fixture(autouse=True)
def _clear_discovery_cache() -> None:
    _DISCOVERY_CACHE.clear()


@pytest.fixture
def idp() -> MockIdP:
    return MockIdP(issuer="https://idp.test", audience="cid")


@pytest.fixture
def patched_httpx(idp: MockIdP, monkeypatch: pytest.MonkeyPatch):
    transport = idp.mock_transport()
    original_init = httpx.AsyncClient.__init__

    def patched(self, *args, **kwargs):  # type: ignore[no-redef]
        kwargs["transport"] = transport
        original_init(self, *args, **kwargs)

    monkeypatch.setattr(httpx.AsyncClient, "__init__", patched)
    return transport


def _build_driver(adapter):
    cfg = GenericOAuthConfig(
        provider_id="mockoidc",
        client_id="cid",
        client_secret="csec",
        discovery_url="https://idp.test/.well-known/openid-configuration",
        scopes=("openid", "email", "profile"),
    )
    auth = init(
        KerniaOptions(
            database=adapter,
            secret="test-secret",
            base_url="http://localhost",
            plugins=[email_and_password(), generic_oauth([cfg])],
        )
    )
    return auth, ASGIDriver(app=auth.router.mount())


async def test_full_oidc_signin_flow(patched_httpx, idp: MockIdP) -> None:
    adapter = memory_adapter()
    auth, driver = _build_driver(adapter)
    idp.create_user(sub="u-1", email="alice@example.com", name="Alice")

    # 1. Sign-in: builds authorize URL + state, returns 302.
    r = await driver.request("GET", "/oauth2/sign-in/mockoidc")
    assert r.status == 302
    loc = next(v for k, v in r.headers if k.lower() == "location")
    parsed = urlparse(loc)
    qs = parse_qs(parsed.query)
    state_token = qs["state"][0]

    # 2. Simulate the IdP redirect back to our callback. MockIdP issues a code
    # on /token, but for our purposes the callback handler doesn't need a real
    # code: it just forwards it to `exchange_code`, and MockIdP's /token
    # endpoint always returns success regardless of the code value.
    r2 = await driver.request(
        "GET",
        "/oauth2/callback/mockoidc",
        query=f"code=abc&state={state_token}",
    )
    assert r2.status == 302, r2.json() if r2.body else r2.status
    # Session cookie should be set on the response.
    assert any(k.lower() == "set-cookie" for k, _ in r2.headers)

    # 3. The user should now exist in the adapter.
    rows = await adapter.find_many(model="user", where=())
    assert len(rows) == 1
    assert rows[0]["email"] == "alice@example.com"

    accounts = await adapter.find_many(
        model="account",
        where=(Where(field="providerId", value="mockoidc"),),
    )
    assert len(accounts) == 1
    assert accounts[0]["accountId"] == "u-1"


async def test_link_account_flow(patched_httpx, idp: MockIdP) -> None:
    adapter = memory_adapter()
    auth, driver = _build_driver(adapter)

    # First: sign up via email/password to get a session.
    r = await driver.request(
        "POST",
        "/sign-up/email",
        json_body={"email": "bob@example.com", "password": "longpassword"},
    )
    assert r.status == 200
    user = r.json()["user"]

    # Now ask /oauth2/link for an authorize URL (requires session).
    r2 = await driver.request(
        "POST",
        "/oauth2/link",
        json_body={
            "provider_id": "mockoidc",
            "callback_url": "http://localhost/after-link",
        },
    )
    assert r2.status == 200
    url = r2.json()["url"]
    state_token = parse_qs(urlparse(url).query)["state"][0]

    # Pretend the user came back from the IdP.
    idp.create_user(sub="u-link", email="bob+oidc@example.com")
    r3 = await driver.request(
        "GET",
        "/oauth2/callback/mockoidc",
        query=f"code=abc&state={state_token}",
    )
    assert r3.status == 302

    # The new account row should be linked to bob.
    accounts = await adapter.find_many(
        model="account",
        where=(Where(field="userId", value=user["id"]),),
    )
    provider_ids = {a["providerId"] for a in accounts}
    assert "mockoidc" in provider_ids
    assert "credential" in provider_ids
