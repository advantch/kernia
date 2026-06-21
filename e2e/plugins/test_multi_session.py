"""End-to-end: multi-session list / switch / revoke flow over ASGI."""

from __future__ import annotations

import pytest
from kernia.auth import init
from kernia.plugins import email_and_password, multi_session
from kernia.types.init_options import KerniaOptions
from kernia_test_utils import ASGIDriver
from kernia_test_utils.adapter_fixtures import all_adapters_param


@pytest.mark.parametrize(*all_adapters_param())
async def test_multi_session_full_lifecycle(adapter_factory) -> None:
    adapter = await adapter_factory()
    auth = init(
        KerniaOptions(
            database=adapter,
            secret="test-secret",
            plugins=[email_and_password(), multi_session(maximum=5)],
        )
    )
    driver = ASGIDriver(app=auth.router.mount())

    # Sign up Alice — first device session.
    r = await driver.request(
        "POST",
        "/sign-up/email",
        json_body={"email": "alice@example.com", "password": "alicepw1"},
    )
    assert r.status == 200, r.json()
    assert "better-auth.session_list" in driver.cookies

    # Sign up Bob from the same browser — new session is added to the list.
    r = await driver.request(
        "POST",
        "/sign-up/email",
        json_body={"email": "bob@example.com", "password": "bobpw1234"},
    )
    assert r.status == 200, r.json()

    # List should contain both.
    r = await driver.request("GET", "/multi-session/list")
    assert r.status == 200, r.json()
    sessions = r.json()["sessions"]
    assert len(sessions) == 2
    user_emails = {s["user"]["email"] for s in sessions if s.get("user")}
    assert user_emails == {"alice@example.com", "bob@example.com"}
    # Bob signed up most recently so he is the active session.
    active = [s for s in sessions if s["isActive"]]
    assert len(active) == 1
    assert active[0]["user"]["email"] == "bob@example.com"

    # Switch to Alice.
    alice_session = next(s for s in sessions if s["user"]["email"] == "alice@example.com")
    r = await driver.request(
        "POST",
        "/multi-session/switch",
        json_body={"session_id": alice_session["id"]},
    )
    assert r.status == 200, r.json()

    # /get-session now resolves to Alice.
    r = await driver.request("GET", "/get-session")
    assert r.status == 200
    assert r.json()["user"]["email"] == "alice@example.com"

    # Sign out — only Alice's active session is revoked; Bob is promoted to active.
    r = await driver.request("POST", "/sign-out")
    assert r.status == 200

    r = await driver.request("GET", "/get-session")
    assert r.status == 200
    body = r.json()
    assert body is not None
    assert body["user"]["email"] == "bob@example.com"

    # The list now contains only Bob.
    r = await driver.request("GET", "/multi-session/list")
    assert r.status == 200, r.json()
    sessions = r.json()["sessions"]
    assert len(sessions) == 1
    assert sessions[0]["user"]["email"] == "bob@example.com"


@pytest.mark.parametrize(*all_adapters_param())
async def test_multi_session_revoke_non_active(adapter_factory) -> None:
    adapter = await adapter_factory()
    auth = init(
        KerniaOptions(
            database=adapter,
            secret="s",
            plugins=[email_and_password(), multi_session()],
        )
    )
    driver = ASGIDriver(app=auth.router.mount())

    await driver.request(
        "POST",
        "/sign-up/email",
        json_body={"email": "u1@example.com", "password": "passpass1"},
    )
    await driver.request(
        "POST",
        "/sign-up/email",
        json_body={"email": "u2@example.com", "password": "passpass2"},
    )

    r = await driver.request("GET", "/multi-session/list")
    sessions = r.json()["sessions"]
    non_active = next(s for s in sessions if not s["isActive"])

    r = await driver.request(
        "POST",
        "/multi-session/revoke",
        json_body={"session_id": non_active["id"]},
    )
    assert r.status == 200, r.json()

    # Active session (u2) survives.
    r = await driver.request("GET", "/get-session")
    assert r.status == 200
    assert r.json()["user"]["email"] == "u2@example.com"
    r = await driver.request("GET", "/multi-session/list")
    assert len(r.json()["sessions"]) == 1
