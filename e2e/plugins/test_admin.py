"""End-to-end tests for the admin plugin."""

from __future__ import annotations

import pytest

from kernia.auth import init
from kernia.plugins.admin import admin
from kernia.plugins.email_password import email_and_password
from kernia.types.adapter import Where
from kernia.types.init_options import KerniaOptions
from kernia_memory_adapter import memory_adapter
from kernia_test_utils import ASGIDriver


async def _build_driver_with_admin() -> tuple[ASGIDriver, object, dict]:
    db = memory_adapter()
    auth = init(
        KerniaOptions(
            database=db,
            secret="test-secret-key",
            plugins=[email_and_password(), admin()],
        )
    )
    driver = ASGIDriver(app=auth.router.mount())
    # Seed an admin via direct sign-up + role bump.
    r = await driver.request(
        "POST",
        "/sign-up/email",
        json_body={"email": "root@example.com", "password": "rootpass!", "name": "Root"},
    )
    assert r.status == 200, r.json()
    admin_user = r.json()["user"]
    await db.update(
        model="user",
        where=(Where(field="id", value=admin_user["id"]),),
        update={"role": "admin"},
    )
    return driver, auth, admin_user


async def test_admin_full_lifecycle() -> None:
    driver, auth, admin_user = await _build_driver_with_admin()

    # 1. create-user
    r = await driver.request(
        "POST",
        "/admin/create-user",
        json_body={
            "email": "bob@example.com",
            "password": "secret123",
            "name": "Bob",
            "role": "user",
        },
    )
    assert r.status == 200, r.json()
    bob_id = r.json()["user"]["id"]

    # 2. list-users includes both
    r = await driver.request("POST", "/admin/list-users", json_body={})
    assert r.status == 200
    assert r.json()["total"] == 2

    # 3. get-user by email
    r = await driver.request(
        "POST", "/admin/get-user", json_body={"email": "bob@example.com"}
    )
    assert r.status == 200
    assert r.json()["id"] == bob_id

    # 4. set-role to admin
    r = await driver.request(
        "POST", "/admin/set-role", json_body={"user_id": bob_id, "role": "user"}
    )
    assert r.status == 200

    # 5. ban-user (no expiry)
    r = await driver.request(
        "POST", "/admin/ban-user", json_body={"user_id": bob_id, "reason": "abuse"}
    )
    assert r.status == 200
    assert r.json()["user"]["banned"] is True

    # 6. unban
    r = await driver.request(
        "POST", "/admin/unban-user", json_body={"user_id": bob_id}
    )
    assert r.status == 200
    assert r.json()["user"]["banned"] is False

    # 7. set-user-password
    r = await driver.request(
        "POST",
        "/admin/set-user-password",
        json_body={"user_id": bob_id, "new_password": "newpass789"},
    )
    assert r.status == 200

    # 8. impersonate
    r = await driver.request(
        "POST", "/admin/impersonate-user", json_body={"user_id": bob_id}
    )
    assert r.status == 200, r.json()
    body = r.json()
    assert body["session"]["impersonatedBy"] == admin_user["id"]
    # The session cookie now points at bob.
    r = await driver.request("GET", "/get-session")
    assert r.status == 200
    assert r.json()["user"]["id"] == bob_id

    # 9. stop-impersonating restores the admin session
    r = await driver.request("POST", "/admin/stop-impersonating")
    assert r.status == 200
    r = await driver.request("GET", "/get-session")
    assert r.status == 200
    assert r.json()["user"]["id"] == admin_user["id"]

    # 10. list-user-sessions for bob
    r = await driver.request(
        "POST", "/admin/list-user-sessions", json_body={"user_id": bob_id}
    )
    assert r.status == 200
    sessions = r.json()["sessions"]
    # Bob's impersonation session was revoked already.
    assert all(not s.get("impersonatedBy") for s in sessions)

    # 11. has-permission
    r = await driver.request(
        "POST",
        "/admin/has-permission",
        json_body={"permissions": {"user": ["ban"]}},
    )
    assert r.status == 200
    assert r.json()["success"] is True

    # 12. remove-user
    r = await driver.request(
        "POST", "/admin/remove-user", json_body={"user_id": bob_id}
    )
    assert r.status == 200


async def test_non_admin_cannot_access() -> None:
    driver, auth, _admin = await _build_driver_with_admin()
    # Sign out the admin and sign up a regular user.
    await driver.request("POST", "/sign-out")
    driver.cookies.clear()
    r = await driver.request(
        "POST",
        "/sign-up/email",
        json_body={"email": "eve@example.com", "password": "evepassword"},
    )
    assert r.status == 200
    r = await driver.request("POST", "/admin/list-users", json_body={})
    assert r.status == 403
    assert r.json()["code"] == "YOU_ARE_NOT_ALLOWED_TO_LIST_USERS"


async def test_banned_user_cannot_use_session() -> None:
    driver, auth, _admin = await _build_driver_with_admin()
    # Create a victim user via admin endpoint.
    r = await driver.request(
        "POST",
        "/admin/create-user",
        json_body={"email": "victim@x.com", "password": "victimpassword", "role": "user"},
    )
    assert r.status == 200
    victim_id = r.json()["user"]["id"]

    # Sign out admin and sign in as victim.
    await driver.request("POST", "/sign-out")
    driver.cookies.clear()
    r = await driver.request(
        "POST",
        "/sign-in/email",
        json_body={"email": "victim@x.com", "password": "victimpassword"},
    )
    assert r.status == 200

    # Admin bans them — but we're acting as victim now, so first switch back.
    # Easier: ban directly via adapter to simulate the bans-mid-session case.
    import time as _time

    await auth.context.adapter.update(  # type: ignore[attr-defined]
        model="user",
        where=(Where(field="id", value=victim_id),),
        update={"banned": True, "banReason": "x", "banExpires": int(_time.time()) + 60},
    )

    # Any subsequent gated request must now 403 with USER_BANNED.
    r = await driver.request("GET", "/get-session")
    assert r.status == 403
    assert r.json()["code"] == "USER_BANNED"
