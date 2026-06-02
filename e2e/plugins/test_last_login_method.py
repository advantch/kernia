"""last-login-method tests.

Ports `reference/.../last-login-method/last-login-method.test.ts` as closely as
the Python harness allows (in-memory adapter). Cookie name now matches upstream:
`better-auth.last_used_login_method`.

Not ported: the social-OAuth (`/callback/google`) and generic-OAuth
(`/oauth2/callback/:providerId`) database cases, which need a mock OAuth provider
+ account-linking wiring that lives outside this plugin's scope. The path-based
resolver IS exercised via the "failed OAuth callback" negative case.
"""

from __future__ import annotations

from urllib.parse import urlencode

import pytest
from kernia.auth import init
from kernia.plugins import email_and_password, last_login_method, magic_link, siwe
from kernia.types.init_options import KerniaOptions
from kernia_test_utils import ASGIDriver
from kernia_test_utils.adapter_fixtures import all_adapters_param

COOKIE = "better-auth.last_used_login_method"


def _memory():
    from kernia_memory_adapter import memory_adapter

    return memory_adapter()


def _siwe_message(domain: str, address: str, nonce: str) -> str:
    return (
        f"{domain} wants you to sign in with your Ethereum account:\n"
        f"{address}\n\n"
        "Sign-in for tests.\n\n"
        f"URI: https://{domain}\n"
        "Version: 1\n"
        "Chain ID: 1\n"
        f"Nonce: {nonce}\n"
        "Issued At: 2026-05-16T00:00:00Z\n"
    )


async def _siwe_sign_in(driver: ASGIDriver):
    from eth_account import Account
    from eth_account.messages import encode_defunct

    acct = Account.create()
    address = acct.address
    r = await driver.request("GET", "/siwe/nonce", query=f"address={address}")
    nonce = r.json()["nonce"]
    msg = _siwe_message("example.com", address, nonce)
    signed = acct.sign_message(encode_defunct(text=msg))
    r = await driver.request(
        "POST",
        "/siwe/verify",
        json_body={
            "message": msg,
            "signature": signed.signature.hex(),
            "address": address,
        },
    )
    assert r.status == 200, r.json()
    return r.json()["token"], address


# --------------------------------------------------------------------------------------
# Cookie behaviour
# --------------------------------------------------------------------------------------


async def test_should_set_cookie_email() -> None:
    auth = init(
        KerniaOptions(
            database=_memory(),
            secret="s",
            plugins=[email_and_password(), last_login_method()],
        )
    )
    driver = ASGIDriver(app=auth.router.mount())
    await driver.request(
        "POST",
        "/sign-up/email",
        json_body={"email": "u@example.com", "password": "passpass1"},
    )
    driver.cookies.pop(COOKIE, None)
    r = await driver.request(
        "POST",
        "/sign-in/email",
        json_body={"email": "u@example.com", "password": "passpass1"},
    )
    assert r.status == 200, r.json()
    assert driver.cookies.get(COOKIE) == "email"


async def test_should_set_cookie_for_siwe() -> None:
    auth = init(
        KerniaOptions(
            database=_memory(),
            secret="test-secret-key",
            plugins=[last_login_method(), siwe()],
        )
    )
    driver = ASGIDriver(app=auth.router.mount())
    await _siwe_sign_in(driver)
    assert driver.cookies.get(COOKIE) == "siwe"


async def test_should_set_cookie_for_magic_link() -> None:
    from kernia_test_utils import MockSMTP, SentEmail

    smtp = MockSMTP()

    async def send_magic_link(email: str, url: str, token: str) -> None:
        await smtp.send(SentEmail(to=email, subject="m", body=url, meta={"token": token}))

    auth = init(
        KerniaOptions(
            database=_memory(),
            secret="s",
            base_url="http://localhost:3000",
            plugins=[last_login_method(), magic_link()],
            advanced={
                "magic-link": {"send_magic_link": send_magic_link, "expires_in": 60},
                "disable_csrf_check": True,
            },
        )
    )
    driver = ASGIDriver(app=auth.router.mount())
    await driver.request(
        "POST", "/sign-in/magic-link", json_body={"email": "ml@example.com"}
    )
    token = smtp.sent[0].meta["token"]
    await driver.request("GET", "/magic-link/verify", query=urlencode({"token": token}))
    assert driver.cookies.get(COOKIE) == "magic-link"


# --------------------------------------------------------------------------------------
# storeInDatabase
# --------------------------------------------------------------------------------------


async def test_store_in_database_email() -> None:
    auth = init(
        KerniaOptions(
            database=_memory(),
            secret="s",
            plugins=[email_and_password(), last_login_method(store_in_database=True)],
        )
    )
    driver = ASGIDriver(app=auth.router.mount())
    await driver.request(
        "POST",
        "/sign-up/email",
        json_body={"email": "db@example.com", "password": "passpass1", "name": "x"},
    )
    r = await driver.request("GET", "/get-session")
    assert r.status == 200
    assert r.json()["user"]["lastLoginMethod"] == "email"


async def test_store_in_database_siwe() -> None:
    auth = init(
        KerniaOptions(
            database=_memory(),
            secret="test-secret-key",
            plugins=[
                email_and_password(),
                last_login_method(store_in_database=True),
                siwe(),
            ],
        )
    )
    driver = ASGIDriver(app=auth.router.mount())
    _token, _address = await _siwe_sign_in(driver)
    r = await driver.request("GET", "/get-session")
    assert r.status == 200, r.json()
    assert r.json()["user"]["lastLoginMethod"] == "siwe"


async def test_store_in_database_magic_link() -> None:
    from kernia_test_utils import MockSMTP, SentEmail

    smtp = MockSMTP()

    async def send_magic_link(email: str, url: str, token: str) -> None:
        await smtp.send(SentEmail(to=email, subject="m", body=url, meta={"token": token}))

    auth = init(
        KerniaOptions(
            database=_memory(),
            secret="s",
            base_url="http://localhost:3000",
            plugins=[
                email_and_password(),
                last_login_method(store_in_database=True),
                magic_link(),
            ],
            advanced={
                "magic-link": {"send_magic_link": send_magic_link, "expires_in": 60},
                "disable_csrf_check": True,
            },
        )
    )
    driver = ASGIDriver(app=auth.router.mount())
    await driver.request(
        "POST", "/sign-in/magic-link", json_body={"email": "mldb@example.com"}
    )
    token = smtp.sent[0].meta["token"]
    await driver.request("GET", "/magic-link/verify", query=urlencode({"token": token}))
    r = await driver.request("GET", "/get-session")
    assert r.status == 200, r.json()
    assert r.json()["user"]["lastLoginMethod"] == "magic-link"


# --------------------------------------------------------------------------------------
# Negative cases
# --------------------------------------------------------------------------------------


async def test_not_set_on_failed_authentication() -> None:
    auth = init(
        KerniaOptions(
            database=_memory(),
            secret="s",
            plugins=[email_and_password(), last_login_method()],
        )
    )
    driver = ASGIDriver(app=auth.router.mount())
    r = await driver.request(
        "POST",
        "/sign-in/email",
        json_body={"email": "nope@example.com", "password": "wrongpass"},
    )
    assert r.status == 401
    assert COOKIE not in driver.cookies


async def test_not_set_on_failed_oauth_callback() -> None:
    auth = init(
        KerniaOptions(
            database=_memory(),
            secret="s",
            plugins=[email_and_password(), last_login_method()],
        )
    )
    driver = ASGIDriver(app=auth.router.mount())
    r = await driver.request(
        "GET",
        "/callback/google",
        query=urlencode({"code": "invalid-code", "state": "invalid-state"}),
    )
    assert r.status >= 400
    assert COOKIE not in driver.cookies


# --------------------------------------------------------------------------------------
# Custom resolver + subsequent logins
# --------------------------------------------------------------------------------------


async def test_custom_resolve_method() -> None:
    def resolver(ctx):
        return "custom" if ctx.request.path == "/sign-in/email" else None

    auth = init(
        KerniaOptions(
            database=_memory(),
            secret="s",
            plugins=[
                email_and_password(),
                last_login_method(custom_resolve_method=resolver),
            ],
        )
    )
    driver = ASGIDriver(app=auth.router.mount())
    await driver.request(
        "POST",
        "/sign-up/email",
        json_body={"email": "c@example.com", "password": "passpass1"},
    )
    driver.cookies.pop(COOKIE, None)
    await driver.request(
        "POST",
        "/sign-in/email",
        json_body={"email": "c@example.com", "password": "passpass1"},
    )
    assert driver.cookies.get(COOKIE) == "custom"


async def test_update_on_subsequent_logins() -> None:
    auth = init(
        KerniaOptions(
            database=_memory(),
            secret="s",
            plugins=[email_and_password(), last_login_method(store_in_database=True)],
        )
    )
    driver = ASGIDriver(app=auth.router.mount())
    await driver.request(
        "POST",
        "/sign-up/email",
        json_body={"email": "sub@example.com", "password": "password123", "name": "x"},
    )
    r = await driver.request("GET", "/get-session")
    assert r.json()["user"]["lastLoginMethod"] == "email"

    await driver.request("POST", "/sign-out")
    driver.cookies.pop(COOKIE, None)
    await driver.request(
        "POST",
        "/sign-in/email",
        json_body={"email": "sub@example.com", "password": "password123"},
    )
    r = await driver.request("GET", "/get-session")
    assert r.json()["user"]["lastLoginMethod"] == "email"


# --------------------------------------------------------------------------------------
# Adapter-matrix smoke (kept from the original suite)
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(*all_adapters_param())
async def test_last_login_method_cookie_set(adapter_factory) -> None:
    adapter = await adapter_factory()
    auth = init(
        KerniaOptions(
            database=adapter,
            secret="s",
            plugins=[email_and_password(), last_login_method()],
        )
    )
    driver = ASGIDriver(app=auth.router.mount())
    r = await driver.request(
        "POST",
        "/sign-up/email",
        json_body={"email": "matrix@example.com", "password": "passpass1"},
    )
    assert r.status == 200, r.json()
    assert driver.cookies.get(COOKIE) == "email"


@pytest.mark.parametrize(*all_adapters_param())
async def test_last_login_method_not_set_on_failed_signin(adapter_factory) -> None:
    adapter = await adapter_factory()
    auth = init(
        KerniaOptions(
            database=adapter,
            secret="s",
            plugins=[email_and_password(), last_login_method()],
        )
    )
    driver = ASGIDriver(app=auth.router.mount())
    r = await driver.request(
        "POST",
        "/sign-in/email",
        json_body={"email": "nope@example.com", "password": "wrongpass"},
    )
    assert r.status == 401
    assert COOKIE not in driver.cookies
