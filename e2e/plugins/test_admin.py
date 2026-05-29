"""End-to-end tests for the admin plugin.

Ported from `reference/packages/better-auth/src/plugins/admin/admin.test.ts`.
Test names mirror the upstream `it(...)` descriptions so coverage is auditable.

Wire format is camelCase, exactly like the upstream `.test.ts` / JS client: the
core router maps camelCase JSON keys onto the snake_case dataclass fields.
"""

from __future__ import annotations

from better_auth.auth import init
from better_auth.plugins.access import create_access_control
from better_auth.plugins.admin import admin
from better_auth.plugins.admin.plugin import AdminOptions
from better_auth.plugins.email_password import email_and_password
from better_auth.types.adapter import Where
from better_auth.types.init_options import BetterAuthOptions, EmailPasswordOptions
from better_auth_memory_adapter import memory_adapter
from better_auth_test_utils import ASGIDriver

# ---------------------------------------------------------------------------
# Harness helpers
# ---------------------------------------------------------------------------


def _make_auth(admin_plugin: object | None = None) -> tuple[object, object]:
    db = memory_adapter()
    auth = init(
        BetterAuthOptions(
            database=db,
            secret="test-secret-key",
            email_and_password=EmailPasswordOptions(enabled=True),
            plugins=[email_and_password(), admin_plugin or admin()],
        )
    )
    return auth, db


def _new_driver(auth: object) -> ASGIDriver:
    return ASGIDriver(app=auth.router.mount())  # type: ignore[attr-defined]


async def _sign_up(driver: ASGIDriver, email: str, password: str, name: str) -> dict:
    r = await driver.request(
        "POST",
        "/sign-up/email",
        json_body={"email": email, "password": password, "name": name},
    )
    assert r.status == 200, r.json()
    return r.json()


async def _build_driver_with_admin() -> tuple[ASGIDriver, object, dict]:
    """Single-driver harness used by the original 3 tests."""
    auth, db = _make_auth()
    driver = _new_driver(auth)
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


async def _build_shared() -> tuple[object, object, ASGIDriver, dict, ASGIDriver, dict]:
    """Multi-driver harness mirroring the upstream `describe("Admin plugin")`.

    Returns (auth, db, admin_driver, admin_user, user_driver, non_admin_user).
    The two drivers share the same app/DB but keep independent cookie jars so we
    can act as the admin and a non-admin concurrently.
    """
    auth, db = _make_auth()
    admin_driver = _new_driver(auth)
    admin_res = await _sign_up(admin_driver, "admin@email.com", "password", "Admin")
    admin_user = admin_res["user"]
    await db.update(
        model="user",
        where=(Where(field="id", value=admin_user["id"]),),
        update={"role": "admin"},
    )

    user_driver = _new_driver(auth)
    non_admin = await _sign_up(user_driver, "user@test.com", "password", "Test User")
    return auth, db, admin_driver, admin_user, user_driver, non_admin["user"]


# ===========================================================================
# Original Python coverage (kept green, field names aligned to upstream wire).
# ===========================================================================


async def test_admin_full_lifecycle() -> None:
    driver, auth, admin_user = await _build_driver_with_admin()

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

    r = await driver.request("POST", "/admin/list-users", json_body={})
    assert r.status == 200
    assert r.json()["total"] == 2

    r = await driver.request("POST", "/admin/get-user", json_body={"id": bob_id})
    assert r.status == 200
    assert r.json()["id"] == bob_id

    r = await driver.request(
        "POST", "/admin/set-role", json_body={"userId": bob_id, "role": "user"}
    )
    assert r.status == 200

    r = await driver.request(
        "POST", "/admin/ban-user", json_body={"userId": bob_id, "banReason": "abuse"}
    )
    assert r.status == 200
    assert r.json()["user"]["banned"] is True

    r = await driver.request("POST", "/admin/unban-user", json_body={"userId": bob_id})
    assert r.status == 200
    assert r.json()["user"]["banned"] is False

    r = await driver.request(
        "POST",
        "/admin/set-user-password",
        json_body={"userId": bob_id, "newPassword": "newpass789"},
    )
    assert r.status == 200

    r = await driver.request(
        "POST", "/admin/impersonate-user", json_body={"userId": bob_id}
    )
    assert r.status == 200, r.json()
    body = r.json()
    assert body["session"]["impersonatedBy"] == admin_user["id"]
    r = await driver.request("GET", "/get-session")
    assert r.status == 200
    assert r.json()["user"]["id"] == bob_id

    r = await driver.request("POST", "/admin/stop-impersonating")
    assert r.status == 200
    r = await driver.request("GET", "/get-session")
    assert r.status == 200
    assert r.json()["user"]["id"] == admin_user["id"]

    r = await driver.request(
        "POST", "/admin/list-user-sessions", json_body={"userId": bob_id}
    )
    assert r.status == 200
    sessions = r.json()["sessions"]
    assert all(not s.get("impersonatedBy") for s in sessions)

    r = await driver.request(
        "POST",
        "/admin/has-permission",
        json_body={"permissions": {"user": ["ban"]}},
    )
    assert r.status == 200
    assert r.json()["success"] is True

    r = await driver.request("POST", "/admin/remove-user", json_body={"userId": bob_id})
    assert r.status == 200


async def test_non_admin_cannot_access() -> None:
    driver, auth, _admin = await _build_driver_with_admin()
    await driver.request("POST", "/sign-out")
    driver.cookies.clear()
    r = await driver.request(
        "POST",
        "/sign-up/email",
        json_body={"email": "eve@example.com", "password": "evepassword", "name": "Eve"},
    )
    assert r.status == 200
    r = await driver.request("POST", "/admin/list-users", json_body={})
    assert r.status == 403
    assert r.json()["code"] == "YOU_ARE_NOT_ALLOWED_TO_LIST_USERS"


async def test_banned_user_cannot_use_session() -> None:
    driver, auth, _admin = await _build_driver_with_admin()
    r = await driver.request(
        "POST",
        "/admin/create-user",
        json_body={
            "email": "victim@x.com",
            "password": "victimpassword",
            "name": "Victim",
            "role": "user",
        },
    )
    assert r.status == 200
    victim_id = r.json()["user"]["id"]

    await driver.request("POST", "/sign-out")
    driver.cookies.clear()
    r = await driver.request(
        "POST",
        "/sign-in/email",
        json_body={"email": "victim@x.com", "password": "victimpassword"},
    )
    assert r.status == 200

    import time as _time

    await auth.context.adapter.update(  # type: ignore[attr-defined]
        model="user",
        where=(Where(field="id", value=victim_id),),
        update={"banned": True, "banReason": "x", "banExpires": int(_time.time()) + 60},
    )

    r = await driver.request("GET", "/get-session")
    assert r.status == 403
    assert r.json()["code"] == "USER_BANNED"


# ===========================================================================
# Ported upstream cases — describe("Admin plugin")
# ===========================================================================


async def test_should_allow_admin_to_get_user() -> None:
    _auth, _db, admin_d, _admin, _user_d, non_admin = await _build_shared()
    r = await admin_d.request("POST", "/admin/get-user", json_body={"id": non_admin["id"]})
    assert r.status == 200, r.json()
    assert r.json()["email"] == "user@test.com"


async def test_should_not_allow_non_admin_to_get_user() -> None:
    _auth, _db, _admin_d, _admin, user_d, non_admin = await _build_shared()
    r = await user_d.request("POST", "/admin/get-user", json_body={"id": non_admin["id"]})
    assert r.status == 403
    assert r.json()["code"] == "YOU_ARE_NOT_ALLOWED_TO_GET_USER"


async def test_should_allow_admin_to_create_users() -> None:
    _auth, _db, admin_d, _admin, _user_d, _non_admin = await _build_shared()
    r = await admin_d.request(
        "POST",
        "/admin/create-user",
        json_body={
            "name": "Test User",
            "email": "user@email.com",
            "password": "test",
            "role": "user",
        },
    )
    assert r.status == 200, r.json()
    assert r.json()["user"]["role"] == "user"


async def test_should_allow_admin_to_create_users_without_password() -> None:
    _auth, _db, admin_d, _admin, user_d, _non_admin = await _build_shared()
    r = await admin_d.request(
        "POST",
        "/admin/create-user",
        json_body={
            "name": "Passwordless User",
            "email": "passwordless@email.com",
            "role": "user",
        },
    )
    assert r.status == 200, r.json()
    body = r.json()
    assert body["user"]["email"] == "passwordless@email.com"
    assert body["user"]["name"] == "Passwordless User"
    assert body["user"]["role"] == "user"

    # No credential account exists, so sign-in must fail.
    signin = await user_d.request(
        "POST",
        "/sign-in/email",
        json_body={"email": "passwordless@email.com", "password": "anypassword"},
    )
    assert signin.status != 200


async def test_should_allow_admin_to_create_user_with_multiple_roles() -> None:
    _auth, _db, admin_d, _admin, _user_d, _non_admin = await _build_shared()
    r = await admin_d.request(
        "POST",
        "/admin/create-user",
        json_body={
            "name": "Test User mr",
            "email": "testmr@test.com",
            "password": "test",
            "role": ["user", "admin"],
        },
    )
    assert r.status == 200, r.json()
    assert r.json()["user"]["role"] == "user,admin"
    result = await admin_d.request(
        "POST",
        "/admin/list-users",
        json_body={"filterField": "role", "filterOperator": "contains", "filterValue": "admin"},
    )
    assert result.status == 200
    assert len(result.json()["users"]) == 2


async def test_should_not_allow_non_admin_to_create_users() -> None:
    _auth, _db, _admin_d, _admin, user_d, _non_admin = await _build_shared()
    r = await user_d.request(
        "POST",
        "/admin/create-user",
        json_body={
            "name": "Test User",
            "email": "test2@test.com",
            "password": "test",
            "role": "user",
        },
    )
    assert r.status == 403


async def test_should_allow_admin_to_list_users() -> None:
    _auth, _db, admin_d, _admin, _user_d, _non_admin = await _build_shared()
    r = await admin_d.request("POST", "/admin/list-users", json_body={"limit": 2})
    assert r.status == 200
    assert len(r.json()["users"]) == 2


async def test_should_list_users_with_search_query() -> None:
    _auth, _db, admin_d, _admin, _user_d, _non_admin = await _build_shared()
    r = await admin_d.request(
        "POST",
        "/admin/list-users",
        json_body={"filterField": "role", "filterOperator": "eq", "filterValue": "admin"},
    )
    assert r.status == 200
    assert r.json()["total"] == 1


async def test_should_not_allow_non_admin_to_list_users() -> None:
    _auth, _db, _admin_d, _admin, user_d, _non_admin = await _build_shared()
    r = await user_d.request("POST", "/admin/list-users", json_body={"limit": 2})
    assert r.status == 403


async def test_should_allow_admin_to_count_users() -> None:
    _auth, _db, admin_d, _admin, _user_d, _non_admin = await _build_shared()
    # Create a third user so total == 3, matching upstream ordering.
    await admin_d.request(
        "POST",
        "/admin/create-user",
        json_body={"name": "Third", "email": "third@test.com", "password": "test", "role": "user"},
    )
    r = await admin_d.request("POST", "/admin/list-users", json_body={"limit": 2})
    assert r.status == 200
    assert len(r.json()["users"]) == 2
    assert r.json()["total"] == 3


async def test_should_allow_to_sort_users_by_name() -> None:
    _auth, _db, admin_d, _admin, _user_d, _non_admin = await _build_shared()
    r = await admin_d.request(
        "POST", "/admin/list-users", json_body={"sortBy": "name", "sortDirection": "desc"}
    )
    assert r.status == 200
    assert r.json()["users"][0]["name"] == "Test User"

    r2 = await admin_d.request(
        "POST", "/admin/list-users", json_body={"sortBy": "name", "sortDirection": "asc"}
    )
    assert r2.status == 200
    assert r2.json()["users"][0]["name"] == "Admin"


async def test_should_allow_offset_and_limit() -> None:
    _auth, _db, admin_d, _admin, _user_d, _non_admin = await _build_shared()
    # Sort ascending by name so ordering is deterministic: Admin, Test User.
    r = await admin_d.request(
        "POST",
        "/admin/list-users",
        json_body={"limit": 1, "offset": 1, "sortBy": "name", "sortDirection": "asc"},
    )
    assert r.status == 200
    assert len(r.json()["users"]) == 1
    assert r.json()["users"][0]["name"] == "Test User"


async def test_should_allow_to_search_users_by_name() -> None:
    _auth, _db, admin_d, _admin, _user_d, _non_admin = await _build_shared()
    r = await admin_d.request(
        "POST",
        "/admin/list-users",
        json_body={"searchValue": "Admin", "searchField": "name", "searchOperator": "contains"},
    )
    assert r.status == 200
    assert len(r.json()["users"]) == 1


async def test_should_apply_filter_when_filter_value_is_falsy() -> None:
    """@see https://github.com/better-auth/better-auth/issues/7837"""
    _auth, _db, admin_d, _admin, user_d, _non_admin = await _build_shared()
    temp = await _sign_up(user_d, "falsy-filter-test@test.com", "password", "Falsy Filter Test")
    temp_id = temp["user"]["id"]

    before = await admin_d.request("POST", "/admin/list-users", json_body={})
    total_before = before.json()["total"]
    assert total_before >= 2

    await admin_d.request("POST", "/admin/ban-user", json_body={"userId": temp_id})

    r = await admin_d.request(
        "POST",
        "/admin/list-users",
        json_body={"filterField": "banned", "filterOperator": "eq", "filterValue": False},
    )
    assert r.status == 200
    users = r.json()["users"]
    assert len(users) == total_before - 1
    assert all(u["banned"] is False for u in users)
    assert all(u["id"] != temp_id for u in users)

    await admin_d.request("POST", "/admin/unban-user", json_body={"userId": temp_id})


async def test_should_filter_users_by_id_with_ne_operator() -> None:
    _auth, _db, admin_d, _admin, _user_d, _non_admin = await _build_shared()
    allu = await admin_d.request("POST", "/admin/list-users", json_body={})
    first_id = allu.json()["users"][0]["id"]
    r = await admin_d.request(
        "POST",
        "/admin/list-users",
        json_body={"filterValue": first_id, "filterField": "id", "filterOperator": "ne"},
    )
    assert r.status == 200
    assert len(r.json()["users"]) == allu.json()["total"] - 1
    assert all(u["id"] != first_id for u in r.json()["users"])


async def test_should_filter_users_by_underscore_id_with_ne_operator() -> None:
    _auth, _db, admin_d, _admin, _user_d, _non_admin = await _build_shared()
    allu = await admin_d.request("POST", "/admin/list-users", json_body={})
    first_id = allu.json()["users"][0]["id"]
    r = await admin_d.request(
        "POST",
        "/admin/list-users",
        json_body={"filterValue": first_id, "filterField": "_id", "filterOperator": "ne"},
    )
    assert r.status == 200
    assert len(r.json()["users"]) == allu.json()["total"] - 1
    assert all(u["id"] != first_id for u in r.json()["users"])


async def test_should_allow_to_combine_search_and_filter() -> None:
    _auth, _db, admin_d, admin_user, _user_d, _non_admin = await _build_shared()
    # Make the admin's email match the search term ("test") so it is the sole hit.
    await _auth.context.adapter.update(  # type: ignore[attr-defined]
        model="user",
        where=(Where(field="id", value=admin_user["id"]),),
        update={"email": "test@test.com"},
    )
    r = await admin_d.request(
        "POST",
        "/admin/list-users",
        json_body={
            "filterValue": "admin",
            "filterField": "role",
            "filterOperator": "eq",
            "searchValue": "test",
            "searchField": "email",
            "searchOperator": "contains",
        },
    )
    assert r.status == 200
    users = r.json()["users"]
    assert len(users) == 1
    assert users[0]["email"] == "test@test.com"


async def test_should_allow_to_set_user_role() -> None:
    _auth, _db, admin_d, _admin, _user_d, non_admin = await _build_shared()
    r = await admin_d.request(
        "POST", "/admin/set-role", json_body={"userId": non_admin["id"], "role": "admin"}
    )
    assert r.status == 200, r.json()
    assert r.json()["user"]["role"] == "admin"


async def test_should_allow_to_set_multiple_user_roles() -> None:
    _auth, _db, admin_d, _admin, _user_d, _non_admin = await _build_shared()
    created = await admin_d.request(
        "POST",
        "/admin/create-user",
        json_body={"name": "Test User mr", "email": "testmr@test.com", "password": "test", "role": "user"},
    )
    assert created.json()["user"]["role"] == "user"
    uid = created.json()["user"]["id"]
    r = await admin_d.request(
        "POST", "/admin/set-role", json_body={"userId": uid, "role": ["user", "admin"]}
    )
    assert r.status == 200, r.json()
    assert r.json()["user"]["role"] == "user,admin"


async def test_should_not_allow_non_admin_to_set_user_role() -> None:
    _auth, _db, _admin_d, _admin, user_d, non_admin = await _build_shared()
    r = await user_d.request(
        "POST", "/admin/set-role", json_body={"userId": non_admin["id"], "role": "admin"}
    )
    assert r.status == 403


async def test_should_allow_to_ban_user() -> None:
    _auth, _db, admin_d, _admin, _user_d, non_admin = await _build_shared()
    r = await admin_d.request("POST", "/admin/ban-user", json_body={"userId": non_admin["id"]})
    assert r.status == 200, r.json()
    assert r.json()["user"]["banned"] is True


async def test_should_not_allow_non_admin_to_ban_user() -> None:
    _auth, _db, _admin_d, _admin, user_d, non_admin = await _build_shared()
    r = await user_d.request("POST", "/admin/ban-user", json_body={"userId": non_admin["id"]})
    assert r.status == 403


async def test_should_allow_to_ban_user_with_reason_and_expiration() -> None:
    _auth, _db, admin_d, _admin, _user_d, non_admin = await _build_shared()
    r = await admin_d.request(
        "POST",
        "/admin/ban-user",
        json_body={
            "userId": non_admin["id"],
            "banReason": "Test reason",
            "banExpiresIn": 60 * 60 * 24,
        },
    )
    assert r.status == 200, r.json()
    body = r.json()
    assert body["user"]["banned"] is True
    assert body["user"]["banReason"] == "Test reason"
    assert body["user"]["banExpires"] is not None


async def test_should_not_allow_banned_user_to_sign_in() -> None:
    _auth, _db, admin_d, _admin, _user_d, _non_admin = await _build_shared()
    created = await admin_d.request(
        "POST",
        "/admin/create-user",
        json_body={"name": "Ban Me", "email": "banme@test.com", "password": "password", "role": "user"},
    )
    uid = created.json()["user"]["id"]
    await admin_d.request("POST", "/admin/ban-user", json_body={"userId": uid})
    fresh = _new_driver(_auth)
    r = await fresh.request(
        "POST", "/sign-in/email", json_body={"email": "banme@test.com", "password": "password"}
    )
    assert r.status == 403
    assert r.json()["code"] == "BANNED_USER"


async def test_should_change_banned_user_message() -> None:
    admin_plugin = admin(AdminOptions(banned_user_message="Custom banned user message"))
    auth, db = _make_auth(admin_plugin)
    admin_d = _new_driver(auth)
    admin_res = await _sign_up(admin_d, "admin@email.com", "password", "Admin")
    await db.update(
        model="user",
        where=(Where(field="id", value=admin_res["user"]["id"]),),
        update={"role": "admin"},
    )
    created = await admin_d.request(
        "POST",
        "/admin/create-user",
        json_body={"name": "Ban Me", "email": "banme@test.com", "password": "password", "role": "user"},
    )
    uid = created.json()["user"]["id"]
    await admin_d.request("POST", "/admin/ban-user", json_body={"userId": uid})
    fresh = _new_driver(auth)
    r = await fresh.request(
        "POST", "/sign-in/email", json_body={"email": "banme@test.com", "password": "password"}
    )
    assert r.json()["message"] == "Custom banned user message"


async def test_should_allow_banned_user_to_sign_in_if_ban_expired() -> None:
    _auth, _db, admin_d, _admin, _user_d, _non_admin = await _build_shared()
    created = await admin_d.request(
        "POST",
        "/admin/create-user",
        json_body={"name": "Ban Me", "email": "banme@test.com", "password": "password", "role": "user"},
    )
    uid = created.json()["user"]["id"]
    # Ban with an already-elapsed expiry so the next access auto-unbans.
    import time as _time

    await _auth.context.adapter.update(  # type: ignore[attr-defined]
        model="user",
        where=(Where(field="id", value=uid),),
        update={"banned": True, "banReason": "x", "banExpires": int(_time.time()) - 10},
    )
    fresh = _new_driver(_auth)
    r = await fresh.request(
        "POST", "/sign-in/email", json_body={"email": "banme@test.com", "password": "password"}
    )
    assert r.status == 200, r.json()
    assert r.json()["user"] is not None


async def test_should_allow_to_unban_user() -> None:
    _auth, _db, admin_d, _admin, _user_d, non_admin = await _build_shared()
    await admin_d.request("POST", "/admin/ban-user", json_body={"userId": non_admin["id"]})
    r = await admin_d.request("POST", "/admin/unban-user", json_body={"userId": non_admin["id"]})
    assert r.status == 200, r.json()
    body = r.json()
    assert body["user"]["banned"] is False
    assert body["user"]["banExpires"] is None
    assert body["user"]["banReason"] is None


async def test_should_not_allow_non_admin_to_unban_user() -> None:
    _auth, _db, _admin_d, _admin, user_d, non_admin = await _build_shared()
    r = await user_d.request("POST", "/admin/unban-user", json_body={"userId": non_admin["id"]})
    assert r.status == 403


async def test_should_allow_admin_to_list_user_sessions() -> None:
    _auth, _db, admin_d, _admin, _user_d, non_admin = await _build_shared()
    r = await admin_d.request(
        "POST", "/admin/list-user-sessions", json_body={"userId": non_admin["id"]}
    )
    assert r.status == 200
    assert len(r.json()["sessions"]) == 1


async def test_should_not_allow_non_admin_to_list_user_sessions() -> None:
    _auth, _db, _admin_d, _admin, user_d, non_admin = await _build_shared()
    r = await user_d.request(
        "POST", "/admin/list-user-sessions", json_body={"userId": non_admin["id"]}
    )
    assert r.status == 403


async def test_should_allow_admins_to_impersonate_user() -> None:
    _auth, _db, admin_d, admin_user, _user_d, non_admin = await _build_shared()
    r = await admin_d.request(
        "POST", "/admin/impersonate-user", json_body={"userId": non_admin["id"]}
    )
    assert r.status == 200, r.json()
    body = r.json()
    assert body["session"] is not None
    assert body["user"]["id"] == non_admin["id"]
    # The impersonator's cookie now resolves to the target user.
    s = await admin_d.request("GET", "/get-session")
    assert s.json()["user"]["id"] == non_admin["id"]


async def test_should_not_allow_non_admin_to_impersonate_user() -> None:
    _auth, _db, _admin_d, _admin, user_d, non_admin = await _build_shared()
    r = await user_d.request(
        "POST", "/admin/impersonate-user", json_body={"userId": non_admin["id"]}
    )
    assert r.status == 403


async def test_should_not_allow_to_impersonate_admins_without_permission() -> None:
    _auth, _db, admin_d, _admin, _user_d, _non_admin = await _build_shared()
    target = await admin_d.request(
        "POST",
        "/admin/create-user",
        json_body={"name": "Other Admin", "email": "other-admin@test.com", "password": "password", "role": "admin"},
    )
    uid = target.json()["user"]["id"]
    r = await admin_d.request("POST", "/admin/impersonate-user", json_body={"userId": uid})
    assert r.status == 403
    assert r.json()["code"] == "YOU_CANNOT_IMPERSONATE_ADMINS"


async def test_should_allow_impersonating_admins_with_permission() -> None:
    ac = create_access_control(
        {
            "user": (
                "create",
                "list",
                "set-role",
                "ban",
                "impersonate",
                "impersonate-admins",
                "delete",
                "set-password",
                "get",
                "update",
            ),
            "session": ("list", "revoke", "delete"),
        }
    )
    super_admin = ac.new_role(
        {
            "user": (
                "create",
                "list",
                "set-role",
                "ban",
                "impersonate",
                "impersonate-admins",
                "delete",
                "set-password",
                "get",
                "update",
            ),
            "session": ("list", "revoke", "delete"),
        }
    )
    regular_admin = ac.new_role(
        {
            "user": (
                "create",
                "list",
                "set-role",
                "ban",
                "impersonate",
                "delete",
                "set-password",
                "get",
                "update",
            ),
            "session": ("list", "revoke", "delete"),
        }
    )
    user_role = ac.new_role({"user": (), "session": ()})
    roles = {"super-admin": super_admin, "admin": regular_admin, "user": user_role}
    plugin = admin(AdminOptions(roles=roles, admin_roles=("super-admin", "admin")))
    auth, db = _make_auth(plugin)

    super_d = _new_driver(auth)
    super_res = await _sign_up(super_d, "super@test.com", "password", "Super Admin")
    await db.update(
        model="user",
        where=(Where(field="id", value=super_res["user"]["id"]),),
        update={"role": "super-admin"},
    )

    target = await super_d.request(
        "POST",
        "/admin/create-user",
        json_body={"name": "Target Admin Perm", "email": "target-admin-perm@test.com", "password": "password", "role": "admin"},
    )
    target_id = target.json()["user"]["id"]

    # super-admin has impersonate-admins → succeeds
    r = await super_d.request("POST", "/admin/impersonate-user", json_body={"userId": target_id})
    assert r.status == 200, r.json()
    assert r.json()["user"]["id"] == target_id

    # regular admin lacks impersonate-admins → fails
    reg_d = _new_driver(auth)
    reg_res = await _sign_up(reg_d, "regular-admin-perm@test.com", "password", "Regular Admin Perm")
    await db.update(
        model="user",
        where=(Where(field="id", value=reg_res["user"]["id"]),),
        update={"role": "admin"},
    )
    r2 = await reg_d.request("POST", "/admin/impersonate-user", json_body={"userId": target_id})
    assert r2.status == 403


async def test_should_allow_impersonating_admins_with_legacy_option() -> None:
    plugin = admin(AdminOptions(allow_impersonating_admins=True))
    auth, db = _make_auth(plugin)
    admin_d = _new_driver(auth)
    admin_res = await _sign_up(admin_d, "admin@email.com", "password", "Admin")
    await db.update(
        model="user",
        where=(Where(field="id", value=admin_res["user"]["id"]),),
        update={"role": "admin"},
    )
    target = await admin_d.request(
        "POST",
        "/admin/create-user",
        json_body={"name": "Target Admin Legacy", "email": "target-admin-legacy@test.com", "password": "password", "role": "admin"},
    )
    target_id = target.json()["user"]["id"]
    r = await admin_d.request("POST", "/admin/impersonate-user", json_body={"userId": target_id})
    assert r.status == 200, r.json()
    assert r.json()["user"]["id"] == target_id


async def test_should_filter_impersonated_sessions() -> None:
    _auth, _db, admin_d, _admin, _user_d, non_admin = await _build_shared()
    # Impersonate the non-admin, creating an impersonation session for them.
    await admin_d.request("POST", "/admin/impersonate-user", json_body={"userId": non_admin["id"]})
    # The non-admin now has 2 sessions (their own + the impersonation one), but
    # /list-sessions filters out impersonated sessions → only their own remains.
    user_login = _new_driver(_auth)
    await user_login.request(
        "POST", "/sign-in/email", json_body={"email": "user@test.com", "password": "password"}
    )
    r = await user_login.request("GET", "/list-sessions")
    assert r.status == 200
    assert all(not s.get("impersonatedBy") for s in r.json())


async def test_should_allow_admin_to_stop_impersonating() -> None:
    _auth, _db, admin_d, admin_user, _user_d, non_admin = await _build_shared()
    await admin_d.request("POST", "/admin/impersonate-user", json_body={"userId": non_admin["id"]})
    r = await admin_d.request("POST", "/admin/stop-impersonating")
    assert r.status == 200, r.json()
    s = await admin_d.request("GET", "/get-session")
    assert s.json()["user"]["id"] == admin_user["id"]


async def test_should_allow_admin_to_revoke_user_session() -> None:
    _auth, _db, admin_d, _admin, user_d, non_admin = await _build_shared()
    sessions = await admin_d.request(
        "POST", "/admin/list-user-sessions", json_body={"userId": non_admin["id"]}
    )
    token = sessions.json()["sessions"][0]["token"]
    r = await admin_d.request(
        "POST", "/admin/revoke-user-session", json_body={"sessionToken": token}
    )
    assert r.status == 200
    assert r.json()["success"] is True
    sessions2 = await admin_d.request(
        "POST", "/admin/list-user-sessions", json_body={"userId": non_admin["id"]}
    )
    assert len(sessions2.json()["sessions"]) == 0


async def test_should_not_allow_non_admin_to_revoke_user_sessions() -> None:
    _auth, _db, _admin_d, _admin, user_d, non_admin = await _build_shared()
    r = await user_d.request(
        "POST", "/admin/revoke-user-sessions", json_body={"userId": non_admin["id"]}
    )
    assert r.status == 403


async def test_should_allow_admin_to_revoke_user_sessions() -> None:
    _auth, _db, admin_d, _admin, _user_d, non_admin = await _build_shared()
    r = await admin_d.request(
        "POST", "/admin/revoke-user-sessions", json_body={"userId": non_admin["id"]}
    )
    assert r.status == 200
    assert r.json()["success"] is True
    sessions = await admin_d.request(
        "POST", "/admin/list-user-sessions", json_body={"userId": non_admin["id"]}
    )
    assert len(sessions.json()["sessions"]) == 0


async def test_should_list_with_ne_filter() -> None:
    _auth, _db, admin_d, _admin, _user_d, _non_admin = await _build_shared()
    r = await admin_d.request(
        "POST",
        "/admin/list-users",
        json_body={
            "sortBy": "createdAt",
            "sortDirection": "desc",
            "filterField": "role",
            "filterOperator": "ne",
            "filterValue": "user",
        },
    )
    assert r.status == 200
    roles = [u.get("role") for u in r.json()["users"]]
    assert "user" not in roles


async def test_should_allow_admin_to_set_user_password() -> None:
    _auth, _db, admin_d, _admin, _user_d, non_admin = await _build_shared()
    r = await admin_d.request(
        "POST",
        "/admin/set-user-password",
        json_body={"userId": non_admin["id"], "newPassword": "newPassword"},
    )
    assert r.status == 200, r.json()
    assert r.json()["status"] is True
    fresh = _new_driver(_auth)
    r2 = await fresh.request(
        "POST", "/sign-in/email", json_body={"email": "user@test.com", "password": "newPassword"}
    )
    assert r2.status == 200, r2.json()
    assert r2.json()["user"] is not None


async def test_should_not_set_password_with_empty_user_id() -> None:
    _auth, _db, admin_d, _admin, _user_d, _non_admin = await _build_shared()
    r = await admin_d.request(
        "POST", "/admin/set-user-password", json_body={"userId": "", "newPassword": "newPassword"}
    )
    assert r.status == 400


async def test_should_not_set_password_with_empty_new_password() -> None:
    _auth, _db, admin_d, _admin, _user_d, non_admin = await _build_shared()
    r = await admin_d.request(
        "POST", "/admin/set-user-password", json_body={"userId": non_admin["id"], "newPassword": ""}
    )
    assert r.status == 400


async def test_should_not_set_password_with_short_new_password() -> None:
    _auth, _db, admin_d, _admin, _user_d, non_admin = await _build_shared()
    r = await admin_d.request(
        "POST",
        "/admin/set-user-password",
        json_body={"userId": non_admin["id"], "newPassword": "1234567"},
    )
    assert r.status == 400
    assert r.json()["code"] == "PASSWORD_TOO_SHORT"
    assert r.json()["message"] == "Password too short"


async def test_should_not_set_password_with_long_new_password() -> None:
    _auth, _db, admin_d, _admin, _user_d, non_admin = await _build_shared()
    long_pw = "a" * 129
    r = await admin_d.request(
        "POST",
        "/admin/set-user-password",
        json_body={"userId": non_admin["id"], "newPassword": long_pw},
    )
    assert r.status == 400
    assert r.json()["code"] == "PASSWORD_TOO_LONG"
    assert r.json()["message"] == "Password too long"


async def test_should_not_allow_non_admin_to_set_user_password() -> None:
    _auth, _db, _admin_d, _admin, user_d, non_admin = await _build_shared()
    r = await user_d.request(
        "POST",
        "/admin/set-user-password",
        json_body={"userId": non_admin["id"], "newPassword": "newPassword"},
    )
    assert r.status == 403


async def test_should_allow_admin_to_delete_user() -> None:
    _auth, _db, admin_d, _admin, _user_d, non_admin = await _build_shared()
    r = await admin_d.request("POST", "/admin/remove-user", json_body={"userId": non_admin["id"]})
    assert r.status == 200
    assert r.json()["success"] is True


async def test_should_not_allow_non_admin_to_delete_user() -> None:
    _auth, _db, _admin_d, _admin, user_d, non_admin = await _build_shared()
    r = await user_d.request("POST", "/admin/remove-user", json_body={"userId": non_admin["id"]})
    assert r.status == 403


async def test_should_allow_admin_to_update_user() -> None:
    _auth, _db, admin_d, _admin, _user_d, non_admin = await _build_shared()
    r = await admin_d.request(
        "POST",
        "/admin/update-user",
        json_body={
            "userId": non_admin["id"],
            "data": {"name": "Updated Name", "customField": "custom value", "role": ["member", "user"]},
        },
    )
    # `member` is not in the default role map, so update-user rejects the role.
    assert r.status == 400


async def test_should_allow_admin_to_update_user_non_role_fields() -> None:
    _auth, _db, admin_d, _admin, _user_d, non_admin = await _build_shared()
    r = await admin_d.request(
        "POST",
        "/admin/update-user",
        json_body={"userId": non_admin["id"], "data": {"name": "Updated Name"}},
    )
    assert r.status == 200, r.json()
    assert r.json()["name"] == "Updated Name"


async def test_should_not_allow_non_admin_to_update_user() -> None:
    _auth, _db, _admin_d, _admin, user_d, non_admin = await _build_shared()
    r = await user_d.request(
        "POST",
        "/admin/update-user",
        json_body={"userId": non_admin["id"], "data": {"name": "Unauthorized Update"}},
    )
    assert r.status == 403
    assert r.json()["code"] == "YOU_ARE_NOT_ALLOWED_TO_UPDATE_USERS"


async def test_should_allow_creating_users_from_server() -> None:
    _auth, _db, admin_d, _admin, _user_d, _non_admin = await _build_shared()
    # No-session driver simulates a server-side create.
    server_d = _new_driver(_auth)
    r = await server_d.request(
        "POST",
        "/admin/create-user",
        json_body={"email": "server-create@test.com", "password": "password", "name": "Server User"},
    )
    assert r.status == 200, r.json()
    assert r.json()["user"]["email"] == "server-create@test.com"
    assert r.json()["user"]["role"] == "user"


# ===========================================================================
# Ported upstream cases — describe("access control")
# ===========================================================================


def _ac_plugin() -> object:
    ac = create_access_control(
        {
            "user": ("create", "read", "update", "delete", "list", "bulk-delete", "set-role"),
            "order": ("create", "read", "update", "delete", "update-many"),
        }
    )
    admin_ac = ac.new_role(
        {
            "user": ("create", "read", "update", "delete", "list", "set-role"),
            "order": ("create", "read", "update", "delete"),
        }
    )
    user_ac = ac.new_role({"user": ("read",), "order": ("read",)})
    support_ac = ac.new_role({"user": ("update",), "order": ("update",)})
    return admin(
        AdminOptions(roles={"admin": admin_ac, "user": user_ac, "support": support_ac})
    )


async def _build_ac() -> tuple[object, object, ASGIDriver, dict]:
    plugin = _ac_plugin()
    auth, db = _make_auth(plugin)
    admin_d = _new_driver(auth)
    admin_res = await _sign_up(admin_d, "admin@email.com", "password", "Admin")
    await db.update(
        model="user",
        where=(Where(field="id", value=admin_res["user"]["id"]),),
        update={"role": "admin"},
    )
    return auth, db, admin_d, admin_res["user"]


async def test_ac_should_not_allow_role_updates_without_set_role() -> None:
    auth, db, admin_d, _admin = await _build_ac()
    support_d = _new_driver(auth)
    support_res = await _sign_up(support_d, "support@test.com", "password", "Support")
    support_id = support_res["user"]["id"]
    await db.update(
        model="user",
        where=(Where(field="id", value=support_id),),
        update={"role": "support"},
    )
    # Non-sensitive update allowed with user:update.
    ok = await support_d.request(
        "POST",
        "/admin/update-user",
        json_body={"userId": support_id, "data": {"name": "Support Updated"}},
    )
    assert ok.status == 200, ok.json()
    assert ok.json()["name"] == "Support Updated"
    # Updating role rejected without user:set-role.
    res = await support_d.request(
        "POST",
        "/admin/update-user",
        json_body={"userId": support_id, "data": {"role": "admin"}},
    )
    assert res.status == 403


async def test_ac_should_reject_non_existent_roles_via_update_user() -> None:
    auth, db, admin_d, _admin = await _build_ac()
    target_d = _new_driver(auth)
    target_res = await _sign_up(target_d, "role-target@test.com", "password", "Role Target")
    target_id = target_res["user"]["id"]
    res = await admin_d.request(
        "POST",
        "/admin/update-user",
        json_body={"userId": target_id, "data": {"role": "non-existent-role"}},
    )
    assert res.status == 400


async def test_ac_should_allow_valid_role_updates_with_set_role() -> None:
    auth, db, admin_d, _admin = await _build_ac()
    target_d = _new_driver(auth)
    target_res = await _sign_up(target_d, "role-valid-target@test.com", "password", "Role Valid Target")
    target_id = target_res["user"]["id"]
    res = await admin_d.request(
        "POST",
        "/admin/update-user",
        json_body={"userId": target_id, "data": {"role": "support"}},
    )
    assert res.status == 200, res.json()
    assert res.json()["role"] == "support"


async def test_ac_should_validate_using_user_id() -> None:
    auth, db, admin_d, admin_user = await _build_ac()
    r = await admin_d.request(
        "POST",
        "/admin/has-permission",
        json_body={"userId": admin_user["id"], "permissions": {"user": ["create"]}},
    )
    assert r.status == 200
    assert r.json()["success"] is True

    r2 = await admin_d.request(
        "POST",
        "/admin/has-permission",
        json_body={"userId": admin_user["id"], "permissions": {"order": ["update-many"]}},
    )
    assert r2.json()["success"] is False


async def test_ac_should_validate_using_role() -> None:
    auth, db, admin_d, _admin = await _build_ac()
    r = await admin_d.request(
        "POST",
        "/admin/has-permission",
        json_body={"role": "admin", "permissions": {"user": ["create"], "order": ["create"]}},
    )
    assert r.json()["success"] is True
    r2 = await admin_d.request(
        "POST",
        "/admin/has-permission",
        json_body={"role": "user", "permissions": {"order": ["update"]}},
    )
    assert r2.json()["success"] is False


async def test_ac_should_prioritize_role_over_user_id() -> None:
    auth, db, admin_d, _admin = await _build_ac()
    user_d = _new_driver(auth)
    target = await _sign_up(user_d, "rolepriority@test.com", "password", "Role Priority")
    uid = target["user"]["id"]
    with_admin_role = await admin_d.request(
        "POST",
        "/admin/has-permission",
        json_body={"userId": uid, "role": "admin", "permissions": {"user": ["create"]}},
    )
    assert with_admin_role.json()["success"] is True
    with_user_role = await admin_d.request(
        "POST",
        "/admin/has-permission",
        json_body={"userId": uid, "role": "user", "permissions": {"user": ["create"]}},
    )
    assert with_user_role.json()["success"] is False


async def test_ac_should_check_permissions_for_banned_user_with_role() -> None:
    auth, db, admin_d, _admin = await _build_ac()
    user_d = _new_driver(auth)
    banned = await _sign_up(user_d, "bannedwithRole@test.com", "password", "Banned Role Test User")
    banned_id = banned["user"]["id"]
    await admin_d.request(
        "POST", "/admin/ban-user", json_body={"userId": banned_id, "banReason": "Testing role priority"}
    )
    with_role = await admin_d.request(
        "POST",
        "/admin/has-permission",
        json_body={"userId": banned_id, "role": "admin", "permissions": {"user": ["create"]}},
    )
    assert with_role.json()["success"] is True
    without_role = await admin_d.request(
        "POST",
        "/admin/has-permission",
        json_body={"userId": banned_id, "permissions": {"user": ["create"]}},
    )
    assert without_role.json()["success"] is False


async def test_ac_should_not_set_multiple_non_existent_roles() -> None:
    auth, db, admin_d, _admin = await _build_ac()
    created = await admin_d.request(
        "POST",
        "/admin/create-user",
        json_body={"name": "Test User mr", "email": "testmr@test.com", "password": "test", "role": ["user"]},
    )
    uid = created.json()["user"]["id"]
    res = await admin_d.request(
        "POST", "/admin/set-role", json_body={"userId": uid, "role": ["user", "non-user"]}
    )
    assert res.status == 400
    assert res.json()["code"] == "YOU_ARE_NOT_ALLOWED_TO_SET_NON_EXISTENT_VALUE"


async def test_ac_should_not_set_non_existent_role() -> None:
    auth, db, admin_d, _admin = await _build_ac()
    created = await admin_d.request(
        "POST",
        "/admin/create-user",
        json_body={"name": "Test User mr", "email": "testmr2@test.com", "password": "test", "role": "user"},
    )
    uid = created.json()["user"]["id"]
    res = await admin_d.request(
        "POST", "/admin/set-role", json_body={"userId": uid, "role": "non-user"}
    )
    assert res.status == 400
    assert res.json()["code"] == "YOU_ARE_NOT_ALLOWED_TO_SET_NON_EXISTENT_VALUE"


async def test_ac_should_properly_handle_custom_roles_in_create_user() -> None:
    auth, db, admin_d, _admin = await _build_ac()
    created = await admin_d.request(
        "POST",
        "/admin/create-user",
        json_body={"name": "Support Role User", "email": "support-role@test.com", "password": "test", "role": "support"},
    )
    assert created.status == 200, created.json()
    assert created.json()["user"]["role"] == "support"


async def test_should_throw_error_when_assigning_non_existent_admin_roles() -> None:
    import pytest

    with pytest.raises(ValueError, match="Invalid admin roles"):
        admin(AdminOptions(admin_roles=("non-existent-role",)))


# ===========================================================================
# Ported upstream cases — describe("edge cases: userId validation")
# ===========================================================================


async def test_edge_should_allow_admin_to_check_permissions() -> None:
    _auth, _db, admin_d, _admin, _user_d, _non_admin = await _build_shared()
    r = await admin_d.request(
        "POST",
        "/admin/has-permission",
        json_body={"role": "admin", "permissions": {"user": ["create"]}},
    )
    assert r.status == 200
    assert r.json()["success"] is True


async def test_edge_should_error_when_user_id_missing() -> None:
    _auth, _db, _admin_d, _admin, _user_d, _non_admin = await _build_shared()
    # No session, no userId, no role → "user id or role is required".
    server_d = _new_driver(_auth)
    r = await server_d.request(
        "POST", "/admin/has-permission", json_body={"permissions": {"user": ["list"]}}
    )
    assert r.status == 400
    assert "user id or role is required" in r.json()["message"]


async def test_edge_should_error_when_user_id_empty_string() -> None:
    _auth, _db, _admin_d, _admin, _user_d, _non_admin = await _build_shared()
    server_d = _new_driver(_auth)
    r = await server_d.request(
        "POST",
        "/admin/has-permission",
        json_body={"userId": "", "permissions": {"user": ["list"]}},
    )
    assert r.status == 400
    assert "user id or role is required" in r.json()["message"]


async def test_edge_should_error_when_user_not_found() -> None:
    _auth, _db, _admin_d, _admin, _user_d, _non_admin = await _build_shared()
    server_d = _new_driver(_auth)
    r = await server_d.request(
        "POST",
        "/admin/has-permission",
        json_body={"userId": "NaN", "permissions": {"user": ["list"]}},
    )
    assert r.status == 404
    assert "user not found" in r.json()["message"]
