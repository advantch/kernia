"""End-to-end tests for the API key plugin.

Ported from ``reference/packages/api-key/src/api-key.test.ts`` (database-storage
path). Covers create / verify / get / update / delete / list / bulk-purge,
hashing at rest, prefix & name validation, expiry config + enforcement, rate
limiting, remaining countdown + refill, metadata enable/disable, permissions
enforcement, and ``enableSessionForAPIKeys``.

Wire format is camelCase, mirroring upstream.
"""

from __future__ import annotations

import time

from better_auth.auth import init
from better_auth.plugins.email_password import email_and_password
from better_auth.types.adapter import Where
from better_auth.types.init_options import BetterAuthOptions
from better_auth_api_key import (
    ApiKeyOptions,
    KeyExpirationOptions,
    PermissionsOptions,
    RateLimitOptions,
    StartingCharactersConfig,
    api_key,
)
from better_auth_memory_adapter import memory_adapter
from better_auth_test_utils import ASGIDriver

# --------------------------------------------------------------------------- helpers


async def _signed_in_driver(
    options: ApiKeyOptions | None = None,
    *,
    email: str = "user@example.com",
) -> tuple[ASGIDriver, object]:
    db = memory_adapter()
    auth = init(
        BetterAuthOptions(
            database=db,
            secret="test-secret-key",
            plugins=[email_and_password(), api_key(options)],
        )
    )
    driver = ASGIDriver(app=auth.router.mount())
    r = await driver.request(
        "POST",
        "/sign-up/email",
        json_body={"email": email, "password": "secret123"},
    )
    assert r.status == 200, r.json()
    return driver, auth


async def _create(driver: ASGIDriver, **body: object) -> dict:
    r = await driver.request("POST", "/api-key/create", json_body=body)
    assert r.status == 200, r.json()
    return r.json()


# --------------------------------------------------------------------------- create


async def test_should_fail_to_create_api_keys_without_session() -> None:
    db = memory_adapter()
    auth = init(
        BetterAuthOptions(
            database=db,
            secret="test-secret-key",
            plugins=[email_and_password(), api_key()],
        )
    )
    driver = ASGIDriver(app=auth.router.mount())
    r = await driver.request("POST", "/api-key/create", json_body={"name": "x"})
    assert r.status == 401
    assert r.json()["code"] == "UNAUTHORIZED_SESSION"


async def test_should_successfully_create_api_keys_with_session() -> None:
    driver, _ = await _signed_in_driver()
    body = await _create(driver, name="ci-bot")
    assert isinstance(body["key"], str)
    assert len(body["key"]) == 64
    assert body["name"] == "ci-bot"
    assert body["enabled"] is True
    assert body["id"]
    # plaintext key is not the stored hash
    assert "metadata" in body


async def test_should_fail_to_create_api_keys_when_user_id_provided_by_client() -> None:
    driver, _ = await _signed_in_driver()
    r = await driver.request(
        "POST", "/api-key/create", json_body={"name": "x", "userId": "someone"}
    )
    assert r.status == 401
    assert r.json()["code"] == "UNAUTHORIZED_SESSION"


async def test_should_have_real_value_from_rate_limit_enabled() -> None:
    driver, _ = await _signed_in_driver(
        ApiKeyOptions(rate_limit=RateLimitOptions(enabled=False))
    )
    body = await _create(driver, name="x")
    assert body["rateLimitEnabled"] is False


async def test_rate_limit_enabled_true_by_default() -> None:
    driver, _ = await _signed_in_driver()
    body = await _create(driver, name="x")
    assert body["rateLimitEnabled"] is True


async def test_should_require_name_if_configured() -> None:
    driver, _ = await _signed_in_driver(ApiKeyOptions(require_name=True))
    r = await driver.request("POST", "/api-key/create", json_body={})
    assert r.status == 400
    assert r.json()["code"] == "NAME_REQUIRED"


async def test_should_respect_rate_limit_config_from_options() -> None:
    driver, _ = await _signed_in_driver(
        ApiKeyOptions(rate_limit=RateLimitOptions(max_requests=5, time_window=1000))
    )
    body = await _create(driver, name="x")
    assert body["rateLimitMax"] == 5
    assert body["rateLimitTimeWindow"] == 1000


async def test_should_create_with_given_name() -> None:
    driver, _ = await _signed_in_driver()
    body = await _create(driver, name="my-key")
    assert body["name"] == "my-key"


async def test_should_fail_name_shorter_than_min() -> None:
    driver, _ = await _signed_in_driver(ApiKeyOptions(minimum_name_length=3))
    r = await driver.request("POST", "/api-key/create", json_body={"name": "ab"})
    assert r.status == 400
    assert r.json()["code"] == "INVALID_NAME_LENGTH"


async def test_should_fail_name_longer_than_max() -> None:
    driver, _ = await _signed_in_driver(ApiKeyOptions(maximum_name_length=5))
    r = await driver.request("POST", "/api-key/create", json_body={"name": "abcdef"})
    assert r.status == 400
    assert r.json()["code"] == "INVALID_NAME_LENGTH"


async def test_should_create_with_given_prefix() -> None:
    driver, _ = await _signed_in_driver()
    body = await _create(driver, name="x", prefix="hello_")
    assert body["prefix"] == "hello_"
    assert body["key"].startswith("hello_")


async def test_should_fail_prefix_shorter_than_min() -> None:
    driver, _ = await _signed_in_driver(ApiKeyOptions(minimum_prefix_length=3))
    r = await driver.request(
        "POST", "/api-key/create", json_body={"name": "x", "prefix": "a"}
    )
    assert r.status == 400
    assert r.json()["code"] == "INVALID_PREFIX_LENGTH"


async def test_should_fail_prefix_longer_than_max() -> None:
    driver, _ = await _signed_in_driver(ApiKeyOptions(maximum_prefix_length=3))
    r = await driver.request(
        "POST", "/api-key/create", json_body={"name": "x", "prefix": "abcdef"}
    )
    assert r.status == 400
    assert r.json()["code"] == "INVALID_PREFIX_LENGTH"


async def test_should_create_with_custom_expires_in() -> None:
    driver, _ = await _signed_in_driver()
    expires_in = 60 * 60 * 24 * 7  # 7 days in seconds
    body = await _create(driver, name="x", expiresIn=expires_in)
    assert body["expiresAt"] is not None
    # roughly 7 days from now (ms)
    delta = int(body["expiresAt"]) - int(time.time() * 1000)
    assert abs(delta - expires_in * 1000) < 5000


async def test_should_support_disabling_key_hashing() -> None:
    driver, auth = await _signed_in_driver(ApiKeyOptions(disable_key_hashing=True))
    body = await _create(driver, name="x")
    raw = body["key"]
    db = auth.context.adapter  # type: ignore[attr-defined]
    row = await db.find_one(model="apikey", where=(Where(field="id", value=body["id"]),))
    assert row["key"] == raw  # stored verbatim when hashing disabled


async def test_should_verify_with_key_hashing_disabled() -> None:
    driver, _ = await _signed_in_driver(ApiKeyOptions(disable_key_hashing=True))
    raw = (await _create(driver, name="x"))["key"]
    driver.cookies.clear()
    r = await driver.request("POST", "/api-key/verify", json_body={"key": raw})
    assert r.status == 200
    assert r.json()["valid"] is True


async def test_should_fail_custom_expires_when_disabled() -> None:
    driver, _ = await _signed_in_driver(
        ApiKeyOptions(key_expiration=KeyExpirationOptions(disable_custom_expires_time=True))
    )
    r = await driver.request(
        "POST", "/api-key/create", json_body={"name": "x", "expiresIn": 60 * 60 * 24}
    )
    assert r.status == 400
    assert r.json()["code"] == "KEY_DISABLED_EXPIRATION"


async def test_should_fail_expires_in_too_small() -> None:
    driver, _ = await _signed_in_driver(
        ApiKeyOptions(key_expiration=KeyExpirationOptions(min_expires_in=2))
    )
    r = await driver.request(
        "POST", "/api-key/create", json_body={"name": "x", "expiresIn": 60 * 60 * 24}
    )
    assert r.status == 400
    assert r.json()["code"] == "EXPIRES_IN_IS_TOO_SMALL"


async def test_should_fail_expires_in_too_large() -> None:
    driver, _ = await _signed_in_driver(
        ApiKeyOptions(key_expiration=KeyExpirationOptions(max_expires_in=1))
    )
    r = await driver.request(
        "POST", "/api-key/create", json_body={"name": "x", "expiresIn": 60 * 60 * 24 * 5}
    )
    assert r.status == 400
    assert r.json()["code"] == "EXPIRES_IN_IS_TOO_LARGE"


async def test_should_fail_create_with_server_only_refill_from_client() -> None:
    driver, _ = await _signed_in_driver()
    r = await driver.request(
        "POST",
        "/api-key/create",
        json_body={"name": "x", "refillAmount": 10, "refillInterval": 1000},
    )
    assert r.status == 400
    assert r.json()["code"] == "SERVER_ONLY_PROPERTY"


async def test_should_create_with_remaining_when_signed_out_server_path() -> None:
    # Server-path create (no session): allowed to set server-only props + userId.
    db = memory_adapter()
    auth = init(
        BetterAuthOptions(
            database=db,
            secret="test-secret-key",
            plugins=[email_and_password(), api_key()],
        )
    )
    driver = ASGIDriver(app=auth.router.mount())
    r = await driver.request(
        "POST", "/sign-up/email", json_body={"email": "s@example.com", "password": "secret123"}
    )
    uid = r.json()["user"]["id"]
    driver.cookies.clear()
    r = await driver.request(
        "POST",
        "/api-key/create",
        json_body={
            "name": "x",
            "userId": uid,
            "refillAmount": 10,
            "refillInterval": 1000,
            "remaining": 10,
        },
    )
    assert r.status == 200, r.json()
    assert r.json()["remaining"] == 10
    assert r.json()["refillAmount"] == 10


# --------------------------------------------------------------------------- metadata


async def test_should_fail_metadata_when_disabled() -> None:
    driver, _ = await _signed_in_driver()  # metadata disabled by default
    r = await driver.request(
        "POST", "/api-key/create", json_body={"name": "x", "metadata": {"a": 1}}
    )
    assert r.status == 400
    assert r.json()["code"] == "METADATA_DISABLED"


async def test_should_fail_invalid_metadata_type() -> None:
    driver, _ = await _signed_in_driver(ApiKeyOptions(enable_metadata=True))
    r = await driver.request(
        "POST", "/api-key/create", json_body={"name": "x", "metadata": "not-an-object"}
    )
    assert r.status == 400
    assert r.json()["code"] == "INVALID_METADATA_TYPE"


async def test_should_create_with_valid_metadata_object() -> None:
    driver, _ = await _signed_in_driver(ApiKeyOptions(enable_metadata=True))
    body = await _create(driver, name="x", metadata={"foo": "bar", "n": 7})
    assert body["metadata"] == {"foo": "bar", "n": 7}


# --------------------------------------------------------------------------- start chars


async def test_should_have_first_6_chars_as_start() -> None:
    driver, _ = await _signed_in_driver()
    body = await _create(driver, name="x")
    assert body["start"] == body["key"][:6]


async def test_start_is_null_when_should_store_false() -> None:
    driver, _ = await _signed_in_driver(
        ApiKeyOptions(starting_characters_config=StartingCharactersConfig(should_store=False))
    )
    body = await _create(driver, name="x")
    assert body["start"] is None


async def test_uses_defined_characters_length() -> None:
    driver, _ = await _signed_in_driver(
        ApiKeyOptions(
            starting_characters_config=StartingCharactersConfig(characters_length=10)
        )
    )
    body = await _create(driver, name="x")
    assert body["start"] == body["key"][:10]


# --------------------------------------------------------------------------- verify


async def test_verify_invalid_key_fails() -> None:
    driver, _ = await _signed_in_driver()
    r = await driver.request(
        "POST", "/api-key/verify", json_body={"key": "x" * 64}
    )
    assert r.status == 200
    assert r.json()["valid"] is False
    assert r.json()["error"]["code"] == "INVALID_API_KEY"


async def test_verify_valid_key() -> None:
    driver, _ = await _signed_in_driver()
    raw = (await _create(driver, name="x"))["key"]
    driver.cookies.clear()
    r = await driver.request("POST", "/api-key/verify", json_body={"key": raw})
    assert r.status == 200
    assert r.json()["valid"] is True
    assert r.json()["key"]["id"]


async def test_verify_decrements_remaining() -> None:
    # remaining is a server-only prop; create via server path.
    db = memory_adapter()
    auth = init(
        BetterAuthOptions(
            database=db,
            secret="test-secret-key",
            plugins=[email_and_password(), api_key()],
        )
    )
    driver = ASGIDriver(app=auth.router.mount())
    r = await driver.request(
        "POST", "/sign-up/email", json_body={"email": "r@example.com", "password": "secret123"}
    )
    uid = r.json()["user"]["id"]
    driver.cookies.clear()
    r = await driver.request(
        "POST", "/api-key/create", json_body={"name": "x", "userId": uid, "remaining": 3}
    )
    raw = r.json()["key"]
    r = await driver.request("POST", "/api-key/verify", json_body={"key": raw})
    assert r.json()["valid"] is True
    assert r.json()["key"]["remaining"] == 2


async def test_verify_fails_when_no_remaining() -> None:
    db = memory_adapter()
    auth = init(
        BetterAuthOptions(
            database=db,
            secret="test-secret-key",
            plugins=[email_and_password(), api_key()],
        )
    )
    driver = ASGIDriver(app=auth.router.mount())
    r = await driver.request(
        "POST", "/sign-up/email", json_body={"email": "r@example.com", "password": "secret123"}
    )
    uid = r.json()["user"]["id"]
    driver.cookies.clear()
    r = await driver.request(
        "POST", "/api-key/create", json_body={"name": "x", "userId": uid, "remaining": 1}
    )
    raw = r.json()["key"]
    # 1st use -> remaining becomes 0
    await driver.request("POST", "/api-key/verify", json_body={"key": raw})
    # 2nd use -> exhausted / deleted
    r = await driver.request("POST", "/api-key/verify", json_body={"key": raw})
    assert r.json()["valid"] is False


async def test_verify_fails_when_expired() -> None:
    db = memory_adapter()
    auth = init(
        BetterAuthOptions(
            database=db,
            secret="test-secret-key",
            plugins=[email_and_password(), api_key()],
        )
    )
    driver = ASGIDriver(app=auth.router.mount())
    r = await driver.request(
        "POST", "/sign-up/email", json_body={"email": "r@example.com", "password": "secret123"}
    )
    body = await _create(driver, name="x")
    # force-expire the key directly
    await db.update(
        model="apikey",
        where=(Where(field="id", value=body["id"]),),
        update={"expiresAt": int(time.time() * 1000) - 10_000},
    )
    raw = body["key"]
    driver.cookies.clear()
    r = await driver.request("POST", "/api-key/verify", json_body={"key": raw})
    assert r.json()["valid"] is False
    assert r.json()["error"]["code"] == "KEY_EXPIRED"


async def test_verify_fails_when_disabled() -> None:
    driver, auth = await _signed_in_driver()
    body = await _create(driver, name="x")
    db = auth.context.adapter  # type: ignore[attr-defined]
    await db.update(
        model="apikey",
        where=(Where(field="id", value=body["id"]),),
        update={"enabled": False},
    )
    driver.cookies.clear()
    r = await driver.request("POST", "/api-key/verify", json_body={"key": body["key"]})
    assert r.json()["valid"] is False
    assert r.json()["error"]["code"] == "KEY_DISABLED"


# --------------------------------------------------------------------------- rate limit


async def test_rate_limit_exceeded_on_verify() -> None:
    driver, _ = await _signed_in_driver(
        ApiKeyOptions(rate_limit=RateLimitOptions(max_requests=3, time_window=10_000))
    )
    raw = (await _create(driver, name="x"))["key"]
    driver.cookies.clear()
    last = None
    for _ in range(5):
        last = await driver.request("POST", "/api-key/verify", json_body={"key": raw})
    assert last is not None
    assert last.json()["valid"] is False
    assert last.json()["error"]["code"] == "RATE_LIMITED"


# --------------------------------------------------------------------------- get


async def test_get_api_key_by_id() -> None:
    driver, _ = await _signed_in_driver()
    body = await _create(driver, name="x")
    r = await driver.request("GET", "/api-key/get", query=f"id={body['id']}")
    assert r.status == 200, r.json()
    assert r.json()["id"] == body["id"]
    assert "key" not in r.json()  # hash never exposed


async def test_get_nonexistent_key_fails() -> None:
    driver, _ = await _signed_in_driver()
    r = await driver.request("GET", "/api-key/get", query="id=does-not-exist")
    assert r.status == 404
    assert r.json()["code"] == "KEY_NOT_FOUND"


async def test_get_other_users_key_fails() -> None:
    driver, auth = await _signed_in_driver(email="a@example.com")
    body = await _create(driver, name="x")
    # sign in as a different user
    driver.cookies.clear()
    await driver.request(
        "POST", "/sign-up/email", json_body={"email": "b@example.com", "password": "secret123"}
    )
    r = await driver.request("GET", "/api-key/get", query=f"id={body['id']}")
    assert r.status == 404


# --------------------------------------------------------------------------- update


async def test_update_name_with_session() -> None:
    driver, _ = await _signed_in_driver()
    body = await _create(driver, name="x")
    r = await driver.request(
        "POST", "/api-key/update", json_body={"keyId": body["id"], "name": "renamed"}
    )
    assert r.status == 200, r.json()
    assert r.json()["name"] == "renamed"


async def test_update_fail_no_values() -> None:
    driver, _ = await _signed_in_driver()
    body = await _create(driver, name="x")
    r = await driver.request("POST", "/api-key/update", json_body={"keyId": body["id"]})
    assert r.status == 400
    assert r.json()["code"] == "NO_VALUES_TO_UPDATE"


async def test_update_name_too_long_fails() -> None:
    driver, _ = await _signed_in_driver(ApiKeyOptions(maximum_name_length=5))
    body = await _create(driver, name="abc")
    r = await driver.request(
        "POST", "/api-key/update", json_body={"keyId": body["id"], "name": "abcdef"}
    )
    assert r.status == 400
    assert r.json()["code"] == "INVALID_NAME_LENGTH"


async def test_update_enabled_value() -> None:
    driver, _ = await _signed_in_driver()
    body = await _create(driver, name="x")
    r = await driver.request(
        "POST", "/api-key/update", json_body={"keyId": body["id"], "enabled": False}
    )
    assert r.status == 200
    assert r.json()["enabled"] is False


async def test_update_expires_in() -> None:
    driver, _ = await _signed_in_driver()
    body = await _create(driver, name="x")
    expires_in = 60 * 60 * 24 * 10
    r = await driver.request(
        "POST",
        "/api-key/update",
        json_body={"keyId": body["id"], "expiresIn": expires_in},
    )
    assert r.status == 200
    delta = int(r.json()["expiresAt"]) - int(time.time() * 1000)
    assert abs(delta - expires_in * 1000) < 5000


async def test_update_metadata_with_valid_object() -> None:
    driver, _ = await _signed_in_driver(ApiKeyOptions(enable_metadata=True))
    body = await _create(driver, name="x")
    r = await driver.request(
        "POST",
        "/api-key/update",
        json_body={"keyId": body["id"], "metadata": {"k": "v"}},
    )
    assert r.status == 200
    assert r.json()["metadata"] == {"k": "v"}


async def test_update_server_only_prop_from_client_fails() -> None:
    driver, _ = await _signed_in_driver()
    body = await _create(driver, name="x")
    r = await driver.request(
        "POST",
        "/api-key/update",
        json_body={"keyId": body["id"], "rateLimitMax": 99},
    )
    assert r.status == 400
    assert r.json()["code"] == "SERVER_ONLY_PROPERTY"


# --------------------------------------------------------------------------- delete


async def test_delete_without_session_fails() -> None:
    driver, _ = await _signed_in_driver()
    body = await _create(driver, name="x")
    driver.cookies.clear()
    r = await driver.request("POST", "/api-key/delete", json_body={"keyId": body["id"]})
    assert r.status == 401


async def test_delete_with_session() -> None:
    driver, _ = await _signed_in_driver()
    body = await _create(driver, name="x")
    r = await driver.request("POST", "/api-key/delete", json_body={"keyId": body["id"]})
    assert r.status == 200
    assert r.json()["success"] is True
    # gone
    r = await driver.request("GET", "/api-key/get", query=f"id={body['id']}")
    assert r.status == 404


async def test_delete_nonexistent_fails() -> None:
    driver, _ = await _signed_in_driver()
    r = await driver.request("POST", "/api-key/delete", json_body={"keyId": "nope"})
    assert r.status == 404
    assert r.json()["code"] == "KEY_NOT_FOUND"


# --------------------------------------------------------------------------- list


async def test_list_without_session_fails() -> None:
    db = memory_adapter()
    auth = init(
        BetterAuthOptions(
            database=db,
            secret="test-secret-key",
            plugins=[email_and_password(), api_key()],
        )
    )
    driver = ASGIDriver(app=auth.router.mount())
    r = await driver.request("GET", "/api-key/list")
    assert r.status == 401


async def test_list_with_session() -> None:
    driver, _ = await _signed_in_driver()
    await _create(driver, name="a")
    await _create(driver, name="b")
    r = await driver.request("GET", "/api-key/list")
    assert r.status == 200
    data = r.json()
    assert data["total"] == 2
    assert len(data["apiKeys"]) == 2
    assert all("key" not in k for k in data["apiKeys"])


async def test_list_pagination_limit() -> None:
    driver, _ = await _signed_in_driver()
    for i in range(5):
        await _create(driver, name=f"k{i}")
    r = await driver.request("GET", "/api-key/list", query="limit=2")
    data = r.json()
    assert data["total"] == 5
    assert len(data["apiKeys"]) == 2


async def test_list_pagination_offset() -> None:
    driver, _ = await _signed_in_driver()
    for i in range(5):
        await _create(driver, name=f"k{i}")
    r = await driver.request("GET", "/api-key/list", query="offset=3")
    data = r.json()
    assert data["total"] == 5
    assert len(data["apiKeys"]) == 2


async def test_list_offset_exceeds_total() -> None:
    driver, _ = await _signed_in_driver()
    await _create(driver, name="a")
    r = await driver.request("GET", "/api-key/list", query="offset=10")
    data = r.json()
    assert data["apiKeys"] == []
    assert data["total"] == 1


async def test_list_sort_by_name() -> None:
    driver, _ = await _signed_in_driver()
    for name in ("charlie", "alpha", "bravo"):
        await _create(driver, name=name)
    r = await driver.request(
        "GET", "/api-key/list", query="sortBy=name&sortDirection=asc"
    )
    names = [k["name"] for k in r.json()["apiKeys"]]
    assert names == ["alpha", "bravo", "charlie"]


# --------------------------------------------------------------------------- permissions


async def test_create_with_default_permissions() -> None:
    driver, _ = await _signed_in_driver(
        ApiKeyOptions(
            permissions=PermissionsOptions(default_permissions={"files": ["read"]})
        )
    )
    body = await _create(driver, name="x")
    assert body["permissions"] == {"files": ["read"]}


async def test_get_returns_permissions_as_object() -> None:
    driver, _ = await _signed_in_driver(
        ApiKeyOptions(
            permissions=PermissionsOptions(default_permissions={"files": ["read"]})
        )
    )
    body = await _create(driver, name="x")
    r = await driver.request("GET", "/api-key/get", query=f"id={body['id']}")
    assert r.json()["permissions"] == {"files": ["read"]}


async def test_verify_with_matching_permissions() -> None:
    driver, _ = await _signed_in_driver(
        ApiKeyOptions(
            permissions=PermissionsOptions(
                default_permissions={"files": ["read", "write"]}
            )
        )
    )
    raw = (await _create(driver, name="x"))["key"]
    driver.cookies.clear()
    r = await driver.request(
        "POST",
        "/api-key/verify",
        json_body={"key": raw, "permissions": {"files": ["read"]}},
    )
    assert r.json()["valid"] is True


async def test_verify_with_non_matching_permissions() -> None:
    driver, _ = await _signed_in_driver(
        ApiKeyOptions(
            permissions=PermissionsOptions(default_permissions={"files": ["read"]})
        )
    )
    raw = (await _create(driver, name="x"))["key"]
    driver.cookies.clear()
    r = await driver.request(
        "POST",
        "/api-key/verify",
        json_body={"key": raw, "permissions": {"files": ["delete"]}},
    )
    assert r.json()["valid"] is False
    assert r.json()["error"]["code"] == "KEY_NOT_FOUND"


async def test_verify_required_permissions_but_key_has_none() -> None:
    driver, _ = await _signed_in_driver()
    raw = (await _create(driver, name="x"))["key"]
    driver.cookies.clear()
    r = await driver.request(
        "POST",
        "/api-key/verify",
        json_body={"key": raw, "permissions": {"files": ["read"]}},
    )
    assert r.json()["valid"] is False
    assert r.json()["error"]["code"] == "KEY_NOT_FOUND"


# --------------------------------------------------------------------------- refill


async def test_refill_after_interval() -> None:
    db = memory_adapter()
    auth = init(
        BetterAuthOptions(
            database=db,
            secret="test-secret-key",
            plugins=[email_and_password(), api_key()],
        )
    )
    driver = ASGIDriver(app=auth.router.mount())
    r = await driver.request(
        "POST", "/sign-up/email", json_body={"email": "r@example.com", "password": "secret123"}
    )
    uid = r.json()["user"]["id"]
    driver.cookies.clear()
    r = await driver.request(
        "POST",
        "/api-key/create",
        json_body={
            "name": "x",
            "userId": uid,
            "remaining": 1,
            "refillAmount": 10,
            "refillInterval": 1,  # 1ms interval -> refills immediately
        },
    )
    raw = r.json()["key"]
    key_id = r.json()["id"]
    # push lastRefillAt into the past so the interval has elapsed
    await db.update(
        model="apikey",
        where=(Where(field="id", value=key_id),),
        update={"lastRefillAt": int(time.time() * 1000) - 100_000, "remaining": 0},
    )
    r = await driver.request("POST", "/api-key/verify", json_body={"key": raw})
    assert r.json()["valid"] is True
    assert r.json()["key"]["remaining"] == 9  # refilled to 10, then -1


async def test_no_refill_before_interval() -> None:
    db = memory_adapter()
    auth = init(
        BetterAuthOptions(
            database=db,
            secret="test-secret-key",
            plugins=[email_and_password(), api_key()],
        )
    )
    driver = ASGIDriver(app=auth.router.mount())
    r = await driver.request(
        "POST", "/sign-up/email", json_body={"email": "r@example.com", "password": "secret123"}
    )
    uid = r.json()["user"]["id"]
    driver.cookies.clear()
    r = await driver.request(
        "POST",
        "/api-key/create",
        json_body={
            "name": "x",
            "userId": uid,
            "remaining": 5,
            "refillAmount": 10,
            "refillInterval": 10_000_000,  # far future
        },
    )
    raw = r.json()["key"]
    r = await driver.request("POST", "/api-key/verify", json_body={"key": raw})
    assert r.json()["key"]["remaining"] == 4  # no refill, just decrement


# --------------------------------------------------------------------------- bulk purge


async def test_delete_all_expired() -> None:
    driver, auth = await _signed_in_driver()
    body = await _create(driver, name="x")
    db = auth.context.adapter  # type: ignore[attr-defined]
    await db.update(
        model="apikey",
        where=(Where(field="id", value=body["id"]),),
        update={"expiresAt": int(time.time() * 1000) - 10_000},
    )
    r = await driver.request("POST", "/api-key/delete-all-expired-api-keys")
    assert r.status == 200
    assert r.json()["success"] is True
    row = await db.find_one(
        model="apikey", where=(Where(field="id", value=body["id"]),)
    )
    assert row is None


# --------------------------------------------------------------------------- session for api keys


async def test_enable_session_for_api_keys() -> None:
    options = ApiKeyOptions(enable_session_for_api_keys=True, api_key_headers="x-api-key")
    driver, _ = await _signed_in_driver(options)
    body = await _create(driver, name="x")
    raw = body["key"]
    uid = (await driver.request("GET", "/get-session")).json()["user"]["id"]
    driver.cookies.clear()
    r = await driver.request("GET", "/get-session", headers={"x-api-key": raw})
    assert r.status == 200
    assert r.json() is not None
    assert r.json()["user"]["id"] == uid


async def test_no_session_for_api_keys_when_disabled() -> None:
    driver, _ = await _signed_in_driver()  # disabled by default
    raw = (await _create(driver, name="x"))["key"]
    driver.cookies.clear()
    r = await driver.request("GET", "/get-session", headers={"x-api-key": raw})
    # Without the hook, no session is attached.
    assert r.json() is None
