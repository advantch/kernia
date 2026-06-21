"""E2E tests for the Google One Tap plugin via ASGI + MockIdP.

Uses `MockIdP.id_token_for(...)` to produce a real RS256 id_token, then POSTs it
to /one-tap/callback with the MockIdP's JWKS URL configured.

Also ports the implicit-account-linking security gate cases from
`reference/.../one-tap/one-tap.test.ts` (GHSA-g38m-r43w-p2q7). Upstream stubs
`jose.jwtVerify`; here we mint a real signed token via MockIdP instead.

Not ported: the `account.accountLinking.requireLocalEmailVerified: false` and
`disableImplicitLinking: true` *core-option* variants — the Python core options
model does not expose those two flags, so they are configured on the plugin
(`OneTapOptions`) instead and covered as plugin-option tests below.
"""

from __future__ import annotations

import httpx
import pytest
from kernia.auth import init
from kernia.plugins.email_password import email_and_password
from kernia.plugins.one_tap import OneTapOptions, one_tap
from kernia.types.adapter import Where
from kernia.types.init_options import KerniaOptions
from kernia_memory_adapter import memory_adapter
from kernia_test_utils import ASGIDriver
from kernia_test_utils.mock_idp import MockIdP


@pytest.fixture
def idp() -> MockIdP:
    return MockIdP(issuer="https://test-idp", audience="client-A")


def _auth(idp: MockIdP, *, plugins, **advanced):
    client = httpx.AsyncClient(transport=idp.mock_transport())
    return init(
        KerniaOptions(
            database=memory_adapter(),
            secret="test-secret",
            plugins=plugins,
            advanced={"http_client": client, "disable_csrf_check": True, **advanced},
        )
    )


def _one_tap(idp: MockIdP, **kwargs) -> object:
    return one_tap(
        OneTapOptions(
            client_id="client-A",
            jwks_url="https://test-idp/.well-known/jwks.json",
            issuer="https://test-idp",
            **kwargs,
        )
    )


@pytest.fixture
def driver(idp: MockIdP) -> ASGIDriver:
    auth = _auth(idp, plugins=[_one_tap(idp)])
    return ASGIDriver(app=auth.router.mount())


# --------------------------------------------------------------------------------------
# Core flow
# --------------------------------------------------------------------------------------


async def test_one_tap_creates_user_and_session(driver: ASGIDriver, idp: MockIdP) -> None:
    token = idp.id_token_for(
        "user-123", email="alice@example.com", email_verified=True, name="Alice"
    )
    r = await driver.request("POST", "/one-tap/callback", json_body={"idToken": token})
    assert r.status == 200, r.json()
    body = r.json()
    assert body["user"]["email"] == "alice@example.com"
    assert "session" in body
    assert "better-auth.session_token" in driver.cookies


async def test_one_tap_repeat_returns_existing_user(driver: ASGIDriver, idp: MockIdP) -> None:
    token_1 = idp.id_token_for("user-x", email="x@example.com", email_verified=True, name="X")
    r = await driver.request("POST", "/one-tap/callback", json_body={"idToken": token_1})
    assert r.status == 200
    user_id_1 = r.json()["user"]["id"]
    driver.cookies.clear()

    token_2 = idp.id_token_for("user-x", email="x@example.com", email_verified=True, name="X")
    r = await driver.request("POST", "/one-tap/callback", json_body={"idToken": token_2})
    assert r.status == 200
    assert r.json()["user"]["id"] == user_id_1


async def test_one_tap_verify_alias_still_works(driver: ASGIDriver, idp: MockIdP) -> None:
    token = idp.id_token_for("user-alias", email="alias@example.com", email_verified=True)
    r = await driver.request("POST", "/one-tap/verify", json_body={"idToken": token})
    assert r.status == 200, r.json()


async def test_one_tap_rejects_bad_audience(idp: MockIdP) -> None:
    auth = _auth(
        idp,
        plugins=[
            one_tap(
                OneTapOptions(
                    client_id="DIFFERENT",
                    jwks_url="https://test-idp/.well-known/jwks.json",
                    issuer="https://test-idp",
                )
            )
        ],
    )
    d = ASGIDriver(app=auth.router.mount())
    token = idp.id_token_for("user-y", email="y@example.com", email_verified=True)
    r = await d.request("POST", "/one-tap/callback", json_body={"idToken": token})
    assert r.status == 400


async def test_one_tap_disable_sign_up(idp: MockIdP) -> None:
    auth = _auth(idp, plugins=[_one_tap(idp, disable_sign_up=True)])
    d = ASGIDriver(app=auth.router.mount())
    token = idp.id_token_for("user-z", email="z@example.com", email_verified=True)
    r = await d.request("POST", "/one-tap/callback", json_body={"idToken": token})
    # Upstream throws BAD_GATEWAY (502) when the user does not exist.
    assert r.status == 502


# --------------------------------------------------------------------------------------
# Implicit-account-linking security gate (GHSA-g38m-r43w-p2q7)
# --------------------------------------------------------------------------------------


async def test_rejects_implicit_linking_when_local_user_unverified(idp: MockIdP) -> None:
    auth = _auth(idp, plugins=[email_and_password(), _one_tap(idp)])
    d = ASGIDriver(app=auth.router.mount())
    # Pre-existing UNVERIFIED local user with the same email.
    await d.request(
        "POST",
        "/sign-up/email",
        json_body={
            "email": "one-tap-user@example.com",
            "password": "password123",
            "name": "Pre-existing Unverified",
        },
    )
    d.cookies.clear()
    token = idp.id_token_for(
        "google_sub_one_tap", email="one-tap-user@example.com", email_verified=True
    )
    r = await d.request("POST", "/one-tap/callback", json_body={"idToken": token})
    assert r.status == 401


async def test_allows_implicit_linking_once_local_user_verified(idp: MockIdP) -> None:
    auth = _auth(idp, plugins=[email_and_password(), _one_tap(idp)])
    d = ASGIDriver(app=auth.router.mount())
    await d.request(
        "POST",
        "/sign-up/email",
        json_body={
            "email": "one-tap-verified@example.com",
            "password": "password123",
            "name": "Pre-existing Verified",
        },
    )
    # Force the local user verified (mirrors the databaseHooks emailVerified:true).
    await auth.context.adapter.update(
        model="user",
        where=(Where(field="email", value="one-tap-verified@example.com"),),
        update={"emailVerified": True},
    )
    d.cookies.clear()
    token = idp.id_token_for(
        "google_sub_verified", email="one-tap-verified@example.com", email_verified=True
    )
    r = await d.request("POST", "/one-tap/callback", json_body={"idToken": token})
    assert r.status == 200, r.json()
    accounts = await auth.context.adapter.find_many(
        model="account", where=(Where(field="providerId", value="google"),)
    )
    assert len(accounts) >= 1


async def test_links_when_require_local_email_verified_opted_out(idp: MockIdP) -> None:
    # Plugin-level analogue of accountLinking.requireLocalEmailVerified=false.
    auth = _auth(
        idp,
        plugins=[email_and_password(), _one_tap(idp, require_local_email_verified=False)],
    )
    d = ASGIDriver(app=auth.router.mount())
    await d.request(
        "POST",
        "/sign-up/email",
        json_body={
            "email": "opted-out@example.com",
            "password": "password123",
            "name": "Opted Out",
        },
    )
    d.cookies.clear()
    token = idp.id_token_for("google_sub_opt", email="opted-out@example.com", email_verified=True)
    r = await d.request("POST", "/one-tap/callback", json_body={"idToken": token})
    assert r.status == 200, r.json()
    accounts = await auth.context.adapter.find_many(
        model="account", where=(Where(field="providerId", value="google"),)
    )
    assert len(accounts) >= 1


async def test_honors_disable_implicit_linking(idp: MockIdP) -> None:
    # Plugin-level analogue of accountLinking.disableImplicitLinking=true.
    auth = _auth(idp, plugins=[email_and_password(), _one_tap(idp, disable_implicit_linking=True)])
    d = ASGIDriver(app=auth.router.mount())
    await d.request(
        "POST",
        "/sign-up/email",
        json_body={
            "email": "no-link@example.com",
            "password": "password123",
            "name": "No Link",
        },
    )
    await auth.context.adapter.update(
        model="user",
        where=(Where(field="email", value="no-link@example.com"),),
        update={"emailVerified": True},
    )
    d.cookies.clear()
    token = idp.id_token_for("google_sub_nolink", email="no-link@example.com", email_verified=True)
    r = await d.request("POST", "/one-tap/callback", json_body={"idToken": token})
    assert r.status == 401
    accounts = await auth.context.adapter.find_many(
        model="account", where=(Where(field="providerId", value="google"),)
    )
    assert len(accounts) == 0
