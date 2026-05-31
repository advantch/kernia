"""End-to-end: bearer-token authentication.

Ports `reference/packages/better-auth/src/plugins/bearer/bearer.test.ts` 1:1 plus
keeps the original adapter-matrix smoke tests.
"""

from __future__ import annotations

from urllib.parse import unquote

from kernia.auth import init
from kernia.plugins import bearer, email_and_password
from kernia.types.init_options import KerniaOptions
from kernia_test_utils import ASGIDriver
from kernia_test_utils.adapter_fixtures import all_adapters_param


def _header(r, name: str) -> str | None:
    for k, v in r.headers:
        if k.lower() == name.lower():
            return v
    return None


# --------------------------------------------------------------------------------------
# Original adapter-matrix smoke tests
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(*all_adapters_param())
async def test_bearer_token_authenticates(adapter_factory) -> None:
    adapter = await adapter_factory()
    auth = init(
        KerniaOptions(
            database=adapter,
            secret="bearer-secret",
            plugins=[email_and_password(), bearer()],
        )
    )
    driver = ASGIDriver(app=auth.router.mount())

    # Sign up via cookie path to obtain a session cookie.
    r = await driver.request(
        "POST",
        "/sign-up/email",
        json_body={"email": "mobile@example.com", "password": "tokens-rule"},
    )
    assert r.status == 200, r.json()
    signed_token = driver.cookies["better-auth.session_token"]

    # Now drop the cookie and replay the same value via Authorization header.
    driver.cookies.clear()
    r = await driver.request(
        "GET",
        "/get-session",
        headers={"Authorization": f"Bearer {signed_token}"},
    )
    assert r.status == 200, r.json()
    body = r.json()
    assert body is not None
    assert body["user"]["email"] == "mobile@example.com"


@pytest.mark.parametrize(*all_adapters_param())
async def test_bearer_invalid_signature_rejected(adapter_factory) -> None:
    adapter = await adapter_factory()
    auth = init(
        KerniaOptions(
            database=adapter,
            secret="bearer-secret",
            plugins=[email_and_password(), bearer()],
        )
    )
    driver = ASGIDriver(app=auth.router.mount())

    await driver.request(
        "POST",
        "/sign-up/email",
        json_body={"email": "x@example.com", "password": "passpass1"},
    )
    signed_token = driver.cookies["better-auth.session_token"]
    driver.cookies.clear()

    # Tamper signature.
    tampered = signed_token[:-2] + "XX"
    r = await driver.request(
        "GET",
        "/get-session",
        headers={"Authorization": f"Bearer {tampered}"},
    )
    assert r.status == 200
    assert r.json() is None


# --------------------------------------------------------------------------------------
# Upstream bearer.test.ts (in-memory adapter, single instance shared via fixture)
# --------------------------------------------------------------------------------------


@pytest.fixture
async def bearer_instance():
    from better_auth_memory_adapter import memory_adapter

    auth = init(
        BetterAuthOptions(
            database=memory_adapter(),
            secret="bearer-secret",
            plugins=[email_and_password(), bearer()],
        )
    )
    driver = ASGIDriver(app=auth.router.mount())
    # Sign up to mint a token; capture the `set-auth-token` response header.
    r = await driver.request(
        "POST",
        "/sign-up/email",
        json_body={
            "email": "bearer-user@email.com",
            "password": "password1234",
            "name": "bearer user",
        },
    )
    assert r.status == 200, r.json()
    token = _header(r, "set-auth-token") or ""
    # Clear the cookie jar so subsequent calls rely on the Authorization header.
    driver.cookies.clear()
    return driver, token


async def test_should_get_session(bearer_instance) -> None:
    driver, token = bearer_instance
    assert token
    r = await driver.request(
        "GET",
        "/get-session",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status == 200
    body = r.json()
    assert body is not None
    assert body.get("session") is not None


async def test_should_list_session(bearer_instance) -> None:
    driver, token = bearer_instance
    r = await driver.request(
        "GET",
        "/list-sessions",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status == 200, r.json()
    sessions = r.json()
    assert isinstance(sessions, list)
    assert len(sessions) == 1


async def test_should_work_on_server_actions(bearer_instance) -> None:
    # Lowercase `authorization` header (server-action style).
    driver, token = bearer_instance
    r = await driver.request(
        "GET",
        "/get-session",
        headers={"authorization": f"Bearer {token}"},
    )
    assert r.status == 200
    body = r.json()
    assert body is not None
    assert body.get("session") is not None


async def test_should_work_with_unsigned_value(bearer_instance) -> None:
    # Upstream sends only the value portion (token.split(".")[0]); unsigned tokens
    # are accepted because requireSignature defaults to false.
    driver, token = bearer_instance
    value = token.split(".")[0]
    r = await driver.request(
        "GET",
        "/get-session",
        headers={"authorization": f"Bearer {value}"},
    )
    assert r.status == 200
    body = r.json()
    assert body is not None
    assert body.get("session") is not None


async def test_valid_cookie_overrides_invalid_auth_header(bearer_instance) -> None:
    driver, token = bearer_instance
    r = await driver.request(
        "GET",
        "/get-session",
        headers={
            "Authorization": "Bearer invalid.token",
            "cookie": f"better-auth.session_token={token}",
        },
    )
    assert r.status == 200
    body = r.json()
    assert body is not None
    assert body.get("session") is not None


@pytest.mark.parametrize(
    "prefix",
    ["bearer", "BEARER", "BeArEr", "Bearer "],
    ids=["lowercase", "uppercase", "mixed", "extra-whitespace"],
)
async def test_should_work_with_scheme_prefix(bearer_instance, prefix) -> None:
    driver, token = bearer_instance
    r = await driver.request(
        "GET",
        "/get-session",
        headers={"authorization": f"{prefix} {token}"},
    )
    assert r.status == 200
    body = r.json()
    assert body is not None
    assert body.get("session") is not None


@pytest.mark.parametrize(
    "transform",
    [lambda t: t, lambda t: unquote(t)],
    ids=["raw", "url-decoded"],
)
async def test_should_work_with_encoded_token(bearer_instance, transform) -> None:
    driver, token = bearer_instance
    test_token = transform(token)
    r = await driver.request(
        "GET",
        "/get-session",
        headers={"authorization": f"Bearer {test_token}"},
    )
    assert r.status == 200
    body = r.json()
    assert body is not None
    assert body.get("session") is not None
