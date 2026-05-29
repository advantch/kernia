"""End-to-end test for the built-in `social_providers` flow.

We don't test all ~35 providers against a real network — the per-provider unit
tests in `packages/core/tests/social_providers/test_each_provider.py` already
verify URL construction. Here we exercise the shared `/sign-in/social` →
`/callback/:provider` path against a `MockIdP` using one OIDC provider
constructed via the generic helper.

The MockIdP transports the token and userinfo endpoints, so anything we plug
into `BetterAuthOptions.social_providers` can be driven through the same path.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from better_auth.auth import init
from better_auth.plugins import email_and_password
from better_auth.social_providers._helpers import make_provider
from better_auth.types.init_options import BetterAuthOptions
from better_auth_memory_adapter import memory_adapter
from better_auth_test_utils import ASGIDriver
from better_auth_test_utils.mock_idp import MockIdP


@pytest.fixture
def idp() -> MockIdP:
    return MockIdP(issuer="https://idp.test", audience="cid")


@pytest.fixture
def patched_httpx(idp: MockIdP, monkeypatch: pytest.MonkeyPatch):
    transport = idp.mock_transport()
    original_init = httpx.AsyncClient.__init__

    def patched(self, *args, **kwargs):
        kwargs["transport"] = transport
        original_init(self, *args, **kwargs)

    monkeypatch.setattr(httpx.AsyncClient, "__init__", patched)


def _mock_provider() -> object:
    """An OIDC-flavored provider hard-wired to the MockIdP endpoints."""
    return make_provider(
        id="mockidp",
        name="Mock IdP",
        client_id="cid",
        client_secret="csec",
        authorization_endpoint="https://idp.test/authorize",
        token_endpoint="https://idp.test/token",
        user_info_endpoint="https://idp.test/userinfo",
        scopes=("openid", "email", "profile"),
    )


async def test_signin_and_callback(patched_httpx, idp: MockIdP) -> None:
    adapter = memory_adapter()
    auth = init(
        BetterAuthOptions(
            database=adapter,
            secret="test-secret",
            base_url="http://localhost",
            plugins=[email_and_password()],
            social_providers={"mockidp": _mock_provider()},
        )
    )
    driver = ASGIDriver(app=auth.router.mount())

    # 1. POST /sign-in/social — should return the authorize URL.
    r = await driver.request(
        "POST",
        "/sign-in/social",
        json_body={"provider": "mockidp", "callback_url": "http://localhost/done"},
    )
    assert r.status == 200, r.json()
    url = r.json()["url"]
    state_token = parse_qs(urlparse(url).query)["state"][0]

    # 2. Drive the callback — MockIdP returns a token bundle with id_token + access_token.
    idp.create_user(sub="u-100", email="carol@example.com", name="Carol")
    r2 = await driver.request(
        "GET",
        "/callback/mockidp",
        query=f"code=abc&state={state_token}",
    )
    assert r2.status == 302, r2.body
    # Session cookie should be set.
    assert any(k.lower() == "set-cookie" for k, _ in r2.headers)

    # 3. /list-accounts confirms the row exists.
    r3 = await driver.request("GET", "/list-accounts")
    assert r3.status == 200
    rows = r3.json()
    assert any(row["providerId"] == "mockidp" for row in rows)
