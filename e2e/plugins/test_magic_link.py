"""Magic-link integration tests across every adapter.

Drives the ASGI app via `ASGIDriver` and captures dispatched links with
`MockSMTP`. Each test parametrizes over the adapter matrix exposed by
`all_adapters_param()`; the Postgres and Mongo entries are skipped automatically
when Docker is unavailable.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlencode

import pytest
from kernia.auth import init
from kernia.plugins.magic_link import magic_link
from kernia.types.init_options import KerniaOptions
from kernia_test_utils import (
    ASGIDriver,
    MockSMTP,
    SentEmail,
    all_adapters_param,
)


def _build_driver(adapter: Any, smtp: MockSMTP, *, disable_sign_up: bool = False):
    async def send_magic_link(email: str, url: str, token: str) -> None:
        await smtp.send(
            SentEmail(
                to=email,
                subject="Magic link",
                body=f"Click here: {url}",
                meta={"token": token},
            )
        )

    auth = init(
        KerniaOptions(
            database=adapter,
            secret="test-secret",
            base_url="http://localhost:3000",
            plugins=[magic_link()],
            advanced={
                "magic-link": {
                    "send_magic_link": send_magic_link,
                    "disable_sign_up": disable_sign_up,
                    "expires_in": 60,
                },
                "disable_csrf_check": True,
            },
        )
    )
    return ASGIDriver(app=auth.router.mount()), auth


def _build_with(adapter: Any, magic_opts: dict[str, Any]):
    auth = init(
        KerniaOptions(
            database=adapter,
            secret="test-secret",
            base_url="http://localhost:3000",
            plugins=[magic_link()],
            advanced={"magic-link": magic_opts, "disable_csrf_check": True},
        )
    )
    return ASGIDriver(app=auth.router.mount()), auth


@pytest.mark.parametrize(*all_adapters_param())
async def test_magic_link_happy_path(adapter_factory) -> None:
    adapter = await adapter_factory()
    smtp = MockSMTP()
    driver, _ = _build_driver(adapter, smtp)

    r = await driver.request(
        "POST",
        "/sign-in/magic-link",
        json_body={"email": "alice@example.com", "callbackURL": "/dashboard"},
    )
    assert r.status == 200, r.json()
    assert r.json()["success"] is True
    assert len(smtp.sent) == 1
    token = smtp.sent[0].meta["token"]

    r = await driver.request("GET", "/magic-link/verify", query=urlencode({"token": token}))
    assert r.status == 200, r.json()
    body = r.json()
    assert body["user"]["email"] == "alice@example.com"
    assert body["isNewUser"] is True
    assert "better-auth.session_token" in driver.cookies


@pytest.mark.parametrize(*all_adapters_param())
async def test_magic_link_invalid_token(adapter_factory) -> None:
    adapter = await adapter_factory()
    driver, _ = _build_driver(adapter, MockSMTP())
    r = await driver.request("GET", "/magic-link/verify", query=urlencode({"token": "nope"}))
    assert r.status == 400
    assert r.json()["code"] == "MAGIC_LINK_INVALID"


@pytest.mark.parametrize(*all_adapters_param())
async def test_magic_link_token_consumed_once(adapter_factory) -> None:
    adapter = await adapter_factory()
    smtp = MockSMTP()
    driver, _ = _build_driver(adapter, smtp)
    await driver.request("POST", "/sign-in/magic-link", json_body={"email": "bob@example.com"})
    token = smtp.sent[0].meta["token"]
    r1 = await driver.request("GET", "/magic-link/verify", query=urlencode({"token": token}))
    assert r1.status == 200
    driver.cookies.clear()
    r2 = await driver.request("GET", "/magic-link/verify", query=urlencode({"token": token}))
    assert r2.status == 400
    assert r2.json()["code"] == "MAGIC_LINK_INVALID"


@pytest.mark.parametrize(*all_adapters_param())
async def test_magic_link_sign_up_disabled(adapter_factory) -> None:
    adapter = await adapter_factory()
    smtp = MockSMTP()
    driver, _ = _build_driver(adapter, smtp, disable_sign_up=True)
    await driver.request("POST", "/sign-in/magic-link", json_body={"email": "newbie@example.com"})
    token = smtp.sent[0].meta["token"]
    r = await driver.request("GET", "/magic-link/verify", query=urlencode({"token": token}))
    assert r.status == 403
    assert r.json()["code"] == "MAGIC_LINK_SIGN_UP_DISABLED"


# ----- ported from reference magic-link.test.ts -----


def _captured() -> tuple[list[dict[str, Any]], Any]:
    captured: list[dict[str, Any]] = []

    async def send_magic_link(data: dict[str, Any], ctx: Any = None) -> None:
        # Upstream single-dict signature: (data, ctx).
        captured.append(data)

    return captured, send_magic_link


async def test_send_magic_link_url_and_no_metadata() -> None:
    from kernia_memory_adapter import memory_adapter

    captured, send = _captured()
    driver, _ = _build_with(memory_adapter(), {"send_magic_link": send})
    r = await driver.request("POST", "/sign-in/magic-link", json_body={"email": "a@b.com"})
    assert r.status == 200, r.json()
    assert len(captured) == 1
    assert captured[0]["email"] == "a@b.com"
    assert "http://localhost:3000/magic-link/verify" in captured[0]["url"]
    assert "metadata" not in captured[0]


async def test_metadata_forwarded() -> None:
    from kernia_memory_adapter import memory_adapter

    captured, send = _captured()
    driver, _ = _build_with(memory_adapter(), {"send_magic_link": send})
    r = await driver.request(
        "POST",
        "/sign-in/magic-link",
        json_body={"email": "a@b.com", "metadata": {"inviteId": "123"}},
    )
    assert r.status == 200, r.json()
    assert captured[0]["metadata"] == {"inviteId": "123"}


async def test_custom_generate_token() -> None:
    from kernia_memory_adapter import memory_adapter

    captured, send = _captured()
    driver, _ = _build_with(
        memory_adapter(),
        {"send_magic_link": send, "generate_token": lambda _email: "custom_token"},
    )
    r = await driver.request("POST", "/sign-in/magic-link", json_body={"email": "a@b.com"})
    assert r.status == 200, r.json()
    assert captured[0]["token"] == "custom_token"


async def test_sign_up_with_name() -> None:
    from kernia_memory_adapter import memory_adapter

    captured, send = _captured()
    driver, _ = _build_with(memory_adapter(), {"send_magic_link": send})
    await driver.request(
        "POST",
        "/sign-in/magic-link",
        json_body={"email": "new-email@email.com", "name": "test"},
    )
    token = captured[0]["token"]
    r = await driver.request("GET", "/magic-link/verify", query=urlencode({"token": token}))
    assert r.status == 200, r.json()
    user = r.json()["user"]
    assert user["name"] == "test"
    assert user["email"] == "new-email@email.com"
    assert user["emailVerified"] is True


async def test_store_token_hashed() -> None:
    from kernia.plugins.magic_link.routes import default_key_hasher
    from kernia_memory_adapter import memory_adapter

    captured, send = _captured()
    adapter = memory_adapter()
    driver, _ = _build_with(adapter, {"send_magic_link": send, "store_token": "hashed"})
    await driver.request("POST", "/sign-in/magic-link", json_body={"email": "a@b.com"})
    token = captured[0]["token"]
    # Stored under the hashed identifier; verifying with the plaintext token works.
    from kernia.types.adapter import Where

    hashed = default_key_hasher(token)
    rec = await adapter.find_one(
        model="verification", where=(Where(field="identifier", value=hashed),)
    )
    assert rec is not None
    r = await driver.request("GET", "/magic-link/verify", query=urlencode({"token": token}))
    assert r.status == 200, r.json()


async def test_store_token_custom_hasher() -> None:
    from kernia.types.adapter import Where
    from kernia_memory_adapter import memory_adapter

    captured, send = _captured()
    adapter = memory_adapter()
    driver, _ = _build_with(
        adapter,
        {
            "send_magic_link": send,
            "store_token": {
                "type": "custom-hasher",
                "hash": lambda token: token + "hashed",
            },
        },
    )
    await driver.request("POST", "/sign-in/magic-link", json_body={"email": "a@b.com"})
    token = captured[0]["token"]
    rec = await adapter.find_one(
        model="verification",
        where=(Where(field="identifier", value=f"{token}hashed"),),
    )
    assert rec is not None
    r = await driver.request("GET", "/magic-link/verify", query=urlencode({"token": token}))
    assert r.status == 200, r.json()


async def test_verify_last_magic_link() -> None:
    from kernia_memory_adapter import memory_adapter

    captured, send = _captured()
    driver, _ = _build_with(memory_adapter(), {"send_magic_link": send})
    for _ in range(3):
        await driver.request("POST", "/sign-in/magic-link", json_body={"email": "a@b.com"})
    last_token = captured[-1]["token"]
    r = await driver.request("GET", "/magic-link/verify", query=urlencode({"token": last_token}))
    assert r.status == 200, r.json()
    assert r.json()["session"]["id"]
