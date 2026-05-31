"""Unit tests for the API key plugin's pure helpers.

Endpoint / flow behavior is covered by ``e2e/plugins/test_api_key.py``.
"""

from __future__ import annotations

import pytest

from kernia.auth import init
from kernia.plugins.email_password import email_and_password
from kernia.types.adapter import Where
from kernia.types.init_options import KerniaOptions
from kernia_api_key import api_key, generate_api_key, parse_api_key
from kernia_memory_adapter import memory_adapter
from kernia_test_utils import ASGIDriver


def test_default_key_generator_length_and_alphabet() -> None:
    key = default_key_generator(64, None)
    assert len(key) == 64
    assert key.isalpha()


def test_default_key_generator_applies_prefix() -> None:
    key = default_key_generator(32, "hello_")
    assert key.startswith("hello_")
    assert len(key) == len("hello_") + 32


def test_default_key_hasher_is_deterministic_base64url() -> None:
    a = default_key_hasher("some-key")
    b = default_key_hasher("some-key")
    assert a == b
    # base64url, no padding
    assert "=" not in a
    assert "+" not in a
    assert "/" not in a
    assert default_key_hasher("other") != a


def test_generate_api_key_returns_start() -> None:
    raw, start = generate_api_key(length=64)
    assert len(raw) == 64
    assert start == raw[:6]


def test_generate_api_key_with_prefix() -> None:
    raw, start = generate_api_key(length=16, prefix="pk_")
    assert raw.startswith("pk_")
    assert start == raw[:6]


def test_parse_api_key_handles_empty() -> None:
    assert parse_api_key("") is None
    assert parse_api_key("ba_") is None
    assert parse_api_key("nope_xx_yy") is None
    assert parse_api_key("ba_only") is None


# ----- Integration tests ---------------------------------------------------


async def _signed_in_driver() -> ASGIDriver:
    auth = init(
        KerniaOptions(
            database=memory_adapter(),
            secret="test-secret-key",
            plugins=[email_and_password(), api_key()],
        )
    )
    driver = ASGIDriver(app=auth.router.mount())
    r = await driver.request(
        "POST",
        "/sign-up/email",
        json_body={"email": "user@example.com", "password": "secret123"},
    )
    assert r.status == 200
    return driver


async def test_api_key_create_verify_revoke() -> None:
    driver = await _signed_in_driver()

    # Create
    r = await driver.request(
        "POST",
        "/api-key/create",
        json_body={"name": "ci-bot", "scope": {"scim": True}, "expires_in": 3600},
    )
    assert r.status == 200, r.json()
    body = r.json()
    raw = body["key"]
    key_id = body["id"]
    assert raw.startswith("ba_")
    assert body["keyPrefix"] == raw.split("_")[1]

    # List
    r = await driver.request("GET", "/api-key/list")
    assert r.status == 200
    keys = r.json()["keys"]
    assert any(k["id"] == key_id for k in keys)
    # Hash never exposed
    assert all("keyHash" not in k for k in keys)

    # Verify (no session required)
    driver.cookies.clear()
    r = await driver.request("POST", "/api-key/verify", json_body={"key": raw})
    assert r.status == 200, r.json()
    assert r.json()["valid"] is True
    assert r.json()["scope"] == {"scim": True}

    # Verify bad key
    r = await driver.request("POST", "/api-key/verify", json_body={"key": "ba_aaaa_bbbb"})
    assert r.status == 200
    assert r.json()["valid"] is False

    # Revoke (sign back in)
    r = await driver.request(
        "POST",
        "/sign-in/email",
        json_body={"email": "user@example.com", "password": "secret123"},
    )
    assert r.status == 200
    r = await driver.request("POST", "/api-key/revoke", json_body={"id": key_id})
    assert r.status == 200

    # Verify post-revocation rejected
    driver.cookies.clear()
    r = await driver.request("POST", "/api-key/verify", json_body={"key": raw})
    assert r.json()["valid"] is False


async def test_api_key_header_attaches_session() -> None:
    driver = await _signed_in_driver()
    r = await driver.request("POST", "/api-key/create", json_body={"name": "h"})
    assert r.status == 200
    raw = r.json()["key"]
    user_id_via_session = (await driver.request("GET", "/get-session")).json()["user"]["id"]

    # Drop cookies and authenticate via header
    driver.cookies.clear()
    r = await driver.request("GET", "/get-session", headers={"authorization": f"ApiKey {raw}"})
    assert r.status == 200
    assert r.json() is not None
    assert r.json()["user"]["id"] == user_id_via_session


async def test_revoke_rejects_other_users_key() -> None:
    auth = init(
        KerniaOptions(
            database=memory_adapter(),
            secret="test-secret-key",
            plugins=[email_and_password(), api_key()],
        )
    )
    driver = ASGIDriver(app=auth.router.mount())
    await driver.request(
        "POST",
        "/sign-up/email",
        json_body={"email": "a@example.com", "password": "secret123"},
    )
    r = await driver.request("POST", "/api-key/create", json_body={"name": "a"})
    key_id = r.json()["id"]
    await driver.request("POST", "/sign-out")
    driver.cookies.clear()
    await driver.request(
        "POST",
        "/sign-up/email",
        json_body={"email": "b@example.com", "password": "secret123"},
    )
    r = await driver.request("POST", "/api-key/revoke", json_body={"id": key_id})
    assert r.status == 404
