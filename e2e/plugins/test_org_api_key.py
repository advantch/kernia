"""End-to-end tests for organization-owned API keys.

Ported from:
  * ``reference/packages/api-key/src/api-key.test.ts`` -- describe("organization-owned API keys")
  * ``reference/packages/api-key/src/org-api-key.test.ts``

Org-owned keys use a configuration with ``references="organization"``. Creating,
reading, updating, deleting and listing them is authorized via the organization
plugin's member/role table (owners get full access). Session mocking is only ever
allowed for ``references="user"`` configs.
"""

from __future__ import annotations

import pytest
from kernia.auth import init
from kernia.plugins.email_password import email_and_password
from kernia.plugins.organization import organization
from kernia.types.init_options import KerniaOptions
from kernia_api_key import ApiKeyConfigurationOptions, api_key
from kernia_memory_adapter import memory_adapter
from kernia_test_utils import ASGIDriver

# --------------------------------------------------------------------------- helpers


_USER_ORG_CONFIGS = [
    ApiKeyConfigurationOptions(
        config_id="user-keys", default_prefix="usr_", references="user"
    ),
    ApiKeyConfigurationOptions(
        config_id="org-keys", default_prefix="org_", references="organization"
    ),
]


async def _org_driver(
    configs: list[ApiKeyConfigurationOptions] | None = None,
    *,
    with_org_plugin: bool = True,
    email: str = "owner@example.com",
) -> tuple[ASGIDriver, object]:
    db = memory_adapter()
    plugins: list[object] = [email_and_password()]
    if with_org_plugin:
        plugins.append(organization())
    plugins.append(api_key(list(configs if configs is not None else _USER_ORG_CONFIGS)))
    auth = init(
        KerniaOptions(database=db, secret="test-secret-key", plugins=plugins)
    )
    driver = ASGIDriver(app=auth.router.mount())
    r = await driver.request(
        "POST",
        "/sign-up/email",
        json_body={"email": email, "password": "secret123", "name": "Owner"},
    )
    assert r.status == 200, r.json()
    return driver, auth


async def _create_org(driver: ASGIDriver, name: str, slug: str) -> dict:
    r = await driver.request(
        "POST", "/organization/create", json_body={"name": name, "slug": slug}
    )
    assert r.status == 200, r.json()
    return r.json()


# --------------------------------------------------------------------------- create


async def test_create_org_owned_api_key() -> None:
    driver, _ = await _org_driver()
    org = await _create_org(driver, "Test Org", "test-org")
    r = await driver.request(
        "POST",
        "/api-key/create",
        json_body={"configId": "org-keys", "organizationId": org["id"]},
    )
    assert r.status == 200, r.json()
    body = r.json()
    assert body["configId"] == "org-keys"
    assert body["referenceId"] == org["id"]
    assert body["prefix"] == "org_"


async def test_create_user_owned_api_key() -> None:
    driver, _ = await _org_driver()
    uid = (await driver.request("GET", "/get-session")).json()["user"]["id"]
    r = await driver.request(
        "POST",
        "/api-key/create",
        json_body={"configId": "user-keys"},
    )
    assert r.status == 200, r.json()
    body = r.json()
    assert body["configId"] == "user-keys"
    assert body["referenceId"] == uid
    assert body["prefix"] == "usr_"


async def test_create_org_key_without_org_id_fails() -> None:
    driver, _ = await _org_driver()
    r = await driver.request(
        "POST", "/api-key/create", json_body={"configId": "org-keys"}
    )
    assert r.status == 400
    assert r.json()["code"] == "ORGANIZATION_ID_REQUIRED"


# --------------------------------------------------------------------------- verify


async def test_verify_org_owned_api_key() -> None:
    driver, _ = await _org_driver()
    org = await _create_org(driver, "Verify Org", "verify-org")
    key = (
        await driver.request(
            "POST",
            "/api-key/create",
            json_body={"configId": "org-keys", "organizationId": org["id"]},
        )
    ).json()
    r = await driver.request(
        "POST",
        "/api-key/verify",
        json_body={"key": key["key"], "configId": "org-keys"},
    )
    body = r.json()
    assert body["valid"] is True
    assert body["key"]["configId"] == "org-keys"
    assert body["key"]["referenceId"] == org["id"]


async def test_mixed_user_and_org_keys() -> None:
    driver, _ = await _org_driver()
    uid = (await driver.request("GET", "/get-session")).json()["user"]["id"]
    org = await _create_org(driver, "Mixed Org", "mixed-org")
    user_key = (
        await driver.request(
            "POST", "/api-key/create", json_body={"configId": "user-keys"}
        )
    ).json()
    org_key = (
        await driver.request(
            "POST",
            "/api-key/create",
            json_body={"configId": "org-keys", "organizationId": org["id"]},
        )
    ).json()

    ur = await driver.request(
        "POST",
        "/api-key/verify",
        json_body={"key": user_key["key"], "configId": "user-keys"},
    )
    assert ur.json()["valid"] is True
    assert ur.json()["key"]["referenceId"] == uid

    orr = await driver.request(
        "POST",
        "/api-key/verify",
        json_body={"key": org_key["key"], "configId": "org-keys"},
    )
    assert orr.json()["valid"] is True
    assert orr.json()["key"]["referenceId"] == org["id"]


# --------------------------------------------------------------------------- list


async def test_list_returns_only_user_keys_without_org_id() -> None:
    driver, _ = await _org_driver()
    uid = (await driver.request("GET", "/get-session")).json()["user"]["id"]
    org = await _create_org(driver, "List Org", "list-org")
    await driver.request("POST", "/api-key/create", json_body={"configId": "user-keys"})
    await driver.request(
        "POST",
        "/api-key/create",
        json_body={"configId": "org-keys", "organizationId": org["id"]},
    )
    keys = (await driver.request("GET", "/api-key/list")).json()["apiKeys"]
    assert keys
    for k in keys:
        assert k["configId"] == "user-keys"
        assert k["referenceId"] == uid


async def test_list_org_keys_with_org_id() -> None:
    driver, _ = await _org_driver()
    org = await _create_org(driver, "List Org Keys", "list-org-keys")
    user_key = (
        await driver.request(
            "POST", "/api-key/create", json_body={"configId": "user-keys"}
        )
    ).json()
    await driver.request(
        "POST",
        "/api-key/create",
        json_body={"configId": "org-keys", "organizationId": org["id"], "name": "k1"},
    )
    await driver.request(
        "POST",
        "/api-key/create",
        json_body={"configId": "org-keys", "organizationId": org["id"], "name": "k2"},
    )
    keys = (
        await driver.request(
            "GET", "/api-key/list", query=f"organizationId={org['id']}"
        )
    ).json()["apiKeys"]
    assert len(keys) == 2
    for k in keys:
        assert k["configId"] == "org-keys"
        assert k["referenceId"] == org["id"]
    assert all(k["id"] != user_key["id"] for k in keys)


async def test_filter_org_keys_by_config_id() -> None:
    configs = [
        ApiKeyConfigurationOptions(
            config_id="org-public", default_prefix="pub_", references="organization"
        ),
        ApiKeyConfigurationOptions(
            config_id="org-internal", default_prefix="int_", references="organization"
        ),
    ]
    driver, _ = await _org_driver(configs)
    org = await _create_org(driver, "Filter Org", "filter-org")
    await driver.request(
        "POST",
        "/api-key/create",
        json_body={"configId": "org-public", "organizationId": org["id"]},
    )
    await driver.request(
        "POST",
        "/api-key/create",
        json_body={"configId": "org-internal", "organizationId": org["id"]},
    )
    keys = (
        await driver.request(
            "GET",
            "/api-key/list",
            query=f"organizationId={org['id']}&configId=org-public",
        )
    ).json()["apiKeys"]
    assert len(keys) == 1
    assert keys[0]["configId"] == "org-public"


async def test_owner_can_list_org_keys() -> None:
    driver, _ = await _org_driver()
    org = await _create_org(driver, "Owner Access Org", "owner-access-org")
    r = await driver.request(
        "GET", "/api-key/list", query=f"organizationId={org['id']}"
    )
    assert r.status == 200, r.json()
    assert "apiKeys" in r.json()


async def test_non_member_denied_org_keys() -> None:
    driver, _ = await _org_driver()
    org = await _create_org(driver, "Non Member Org", "non-member-org")

    # Sign in as a different user who is not a member of the org.
    await driver.request(
        "POST",
        "/sign-up/email",
        json_body={
            "email": "stranger@example.com",
            "password": "secret123",
            "name": "Stranger",
        },
    )
    r = await driver.request(
        "GET", "/api-key/list", query=f"organizationId={org['id']}"
    )
    assert r.status in (401, 403)


# --------------------------------------------------------------------------- get / update / delete


async def test_get_org_key_by_id() -> None:
    driver, _ = await _org_driver()
    org = await _create_org(driver, "Get Org", "get-org")
    key = (
        await driver.request(
            "POST",
            "/api-key/create",
            json_body={
                "configId": "org-keys",
                "organizationId": org["id"],
                "name": "my-org-key",
            },
        )
    ).json()
    r = await driver.request(
        "GET", "/api-key/get", query=f"id={key['id']}&configId=org-keys"
    )
    assert r.status == 200, r.json()
    body = r.json()
    assert body["id"] == key["id"]
    assert body["configId"] == "org-keys"
    assert body["referenceId"] == org["id"]
    assert body["name"] == "my-org-key"


async def test_delete_org_key() -> None:
    driver, _ = await _org_driver()
    org = await _create_org(driver, "Delete Org", "delete-org")
    key = (
        await driver.request(
            "POST",
            "/api-key/create",
            json_body={"configId": "org-keys", "organizationId": org["id"]},
        )
    ).json()
    r = await driver.request(
        "POST",
        "/api-key/delete",
        json_body={"keyId": key["id"], "configId": "org-keys"},
    )
    assert r.status == 200, r.json()
    assert r.json()["success"] is True

    v = await driver.request(
        "POST",
        "/api-key/verify",
        json_body={"key": key["key"], "configId": "org-keys"},
    )
    assert v.json()["valid"] is False


async def test_update_org_key() -> None:
    driver, _ = await _org_driver()
    org = await _create_org(driver, "Update Org", "update-org")
    key = (
        await driver.request(
            "POST",
            "/api-key/create",
            json_body={
                "configId": "org-keys",
                "organizationId": org["id"],
                "name": "before",
            },
        )
    ).json()
    r = await driver.request(
        "POST",
        "/api-key/update",
        json_body={"keyId": key["id"], "name": "after", "configId": "org-keys"},
    )
    assert r.status == 200, r.json()
    assert r.json()["name"] == "after"
    assert r.json()["configId"] == "org-keys"


# --------------------------------------------------------------------------- session mocking


async def test_no_session_mocking_for_org_keys() -> None:
    configs = [
        ApiKeyConfigurationOptions(
            config_id="org-keys",
            default_prefix="org_",
            references="organization",
            enable_session_for_api_keys=True,
        )
    ]
    driver, _ = await _org_driver(configs)
    org = await _create_org(driver, "Session Org", "session-org")
    key = (
        await driver.request(
            "POST",
            "/api-key/create",
            json_body={"configId": "org-keys", "organizationId": org["id"]},
        )
    ).json()
    driver.cookies.clear()
    r = await driver.request("GET", "/get-session", headers={"x-api-key": key["key"]})
    # Session mocking only works for user-owned keys.
    assert r.status == 401
    assert r.json()["code"] == "INVALID_REFERENCE_ID_FROM_API_KEY"


async def test_session_mocking_for_user_keys_only() -> None:
    configs = [
        ApiKeyConfigurationOptions(
            config_id="user-keys",
            default_prefix="usr_",
            references="user",
            enable_session_for_api_keys=True,
        )
    ]
    driver, _ = await _org_driver(configs)
    uid = (await driver.request("GET", "/get-session")).json()["user"]["id"]
    key = (
        await driver.request(
            "POST", "/api-key/create", json_body={"configId": "user-keys"}
        )
    ).json()
    driver.cookies.clear()
    r = await driver.request("GET", "/get-session", headers={"x-api-key": key["key"]})
    assert r.status == 200
    assert r.json() is not None
    assert r.json()["user"]["id"] == uid


# --------------------------------------------------------------------------- edge cases


async def test_org_key_without_org_plugin_errors() -> None:
    # Org-referencing config but no organization plugin installed.
    configs = [
        ApiKeyConfigurationOptions(
            config_id="org-keys", default_prefix="org_", references="organization"
        )
    ]
    driver, _ = await _org_driver(configs, with_org_plugin=False)
    r = await driver.request(
        "POST",
        "/api-key/create",
        json_body={"configId": "org-keys", "organizationId": "fake-org"},
    )
    # No org plugin => permission check raises ORGANIZATION_PLUGIN_REQUIRED.
    assert r.status == 500
    assert r.json()["code"] == "ORGANIZATION_PLUGIN_REQUIRED"


async def test_wrong_config_id_for_org_key() -> None:
    driver, _ = await _org_driver()
    org = await _create_org(driver, "Wrong Config Org", "wrong-config-org")
    key = (
        await driver.request(
            "POST",
            "/api-key/create",
            json_body={"configId": "org-keys", "organizationId": org["id"]},
        )
    ).json()
    # Verifying an org-keys key under the user-keys config must fail.
    r = await driver.request(
        "POST",
        "/api-key/verify",
        json_body={"key": key["key"], "configId": "user-keys"},
    )
    assert r.json()["valid"] is False


# --------------------------------------------------------------------------- custom roles (xfail)


@pytest.mark.xfail(
    reason="core organization plugin does not accept ac/roles constructor args; "
    "custom apiKey role permissions cannot be configured from this package",
    strict=False,
)
def test_custom_apikey_role_permissions() -> None:
    # Upstream org-api-key.test.ts describe("custom apiKey permissions in roles")
    # builds the org plugin with createAccessControl()-derived ac + roles. The
    # Python organization() factory exposes neither, so member/admin/restricted
    # custom-permission scenarios are unportable without a core change.
    raise AssertionError("requires core organization ac/roles support")
