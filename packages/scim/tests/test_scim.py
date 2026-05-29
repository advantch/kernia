"""Tests for the SCIM plugin."""

from __future__ import annotations

import pytest
from better_auth.auth import init
from better_auth.plugins.admin import admin
from better_auth.plugins.email_password import email_and_password
from better_auth.types.adapter import Where
from better_auth.types.init_options import BetterAuthOptions
from better_auth_api_key import api_key
from better_auth_memory_adapter import memory_adapter
from better_auth_scim import apply_patch_ops, scim
from better_auth_test_utils import ASGIDriver

# ----- Unit: PatchOp interpreter ------------------------------------------


def test_apply_patch_add_replace_remove() -> None:
    doc: dict = {"name": "alice", "active": True}
    apply_patch_ops(
        doc,
        [
            {"op": "Add", "path": "displayName", "value": "Alice"},
            {"op": "Replace", "path": "name", "value": "Alice Bob"},
            {"op": "Remove", "path": "active"},
        ],
    )
    assert doc == {"name": "Alice Bob", "displayName": "Alice"}


def test_apply_patch_nested_path() -> None:
    doc: dict = {}
    apply_patch_ops(doc, [{"op": "Add", "path": "name.formatted", "value": "X"}])
    assert doc == {"name": {"formatted": "X"}}


def test_apply_patch_bulk_replace_without_path() -> None:
    doc: dict = {"a": 1}
    apply_patch_ops(doc, [{"op": "Replace", "value": {"a": 2, "b": 3}}])
    assert doc == {"a": 2, "b": 3}


def test_apply_patch_unknown_op_raises() -> None:
    with pytest.raises(ValueError):
        apply_patch_ops({}, [{"op": "Mutate", "value": 1}])


# ----- Integration --------------------------------------------------------


async def _admin_driver() -> tuple[ASGIDriver, object]:
    db = memory_adapter()
    auth = init(
        BetterAuthOptions(
            database=db,
            secret="test-secret-key",
            plugins=[email_and_password(), admin(), api_key(), scim()],
        )
    )
    driver = ASGIDriver(app=auth.router.mount())
    r = await driver.request(
        "POST",
        "/sign-up/email",
        json_body={"email": "root@example.com", "password": "rootpass!"},
    )
    assert r.status == 200
    await db.update(
        model="user",
        where=(Where(field="id", value=r.json()["user"]["id"]),),
        update={"role": "admin"},
    )
    return driver, auth


async def test_scim_users_list_and_get() -> None:
    driver, _auth = await _admin_driver()
    # SCIM list
    r = await driver.request("GET", "/scim/v2/Users")
    assert r.status == 200, r.json()
    body = r.json()
    assert body["schemas"] == ["urn:ietf:params:scim:api:messages:2.0:ListResponse"]
    assert body["totalResults"] == 1
    user_id = body["Resources"][0]["id"]
    # GET one
    r = await driver.request("GET", f"/scim/v2/Users/{user_id}")
    assert r.status == 200
    assert r.json()["userName"] == "root@example.com"


async def test_scim_create_replace_patch_delete() -> None:
    driver, _auth = await _admin_driver()
    # Create
    r = await driver.request(
        "POST",
        "/scim/v2/Users",
        json_body={
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "new@example.com",
            "displayName": "New One",
            "name": {"givenName": "New", "familyName": "One"},
        },
    )
    assert r.status == 200, r.json()
    user_id = r.json()["id"]

    # PUT replace
    r = await driver.request(
        "PUT",
        f"/scim/v2/Users/{user_id}",
        json_body={"userName": "new@example.com", "displayName": "Renamed", "active": True},
    )
    assert r.status == 200
    assert r.json()["displayName"] == "Renamed"

    # PATCH replace name
    r = await driver.request(
        "PATCH",
        f"/scim/v2/Users/{user_id}",
        json_body={
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [
                {"op": "Replace", "path": "displayName", "value": "Patched"},
                {"op": "Replace", "path": "active", "value": False},
            ],
        },
    )
    assert r.status == 200, r.json()
    assert r.json()["displayName"] == "Patched"
    assert r.json()["active"] is False

    # DELETE
    r = await driver.request("DELETE", f"/scim/v2/Users/{user_id}")
    assert r.status == 200

    # Confirm gone
    r = await driver.request("GET", f"/scim/v2/Users/{user_id}")
    assert r.status == 404


async def test_scim_service_provider_config() -> None:
    driver, _auth = await _admin_driver()
    r = await driver.request("GET", "/scim/v2/ServiceProviderConfig")
    assert r.status == 200
    assert r.json()["patch"]["supported"] is True
    r = await driver.request("GET", "/scim/v2/ResourceTypes")
    assert r.status == 200
    assert r.json()["totalResults"] == 2
    r = await driver.request("GET", "/scim/v2/Schemas")
    assert r.status == 200


async def test_scim_unauthorized_without_admin() -> None:
    db = memory_adapter()
    auth = init(
        BetterAuthOptions(
            database=db,
            secret="test-secret-key",
            plugins=[email_and_password(), admin(), api_key(), scim()],
        )
    )
    driver = ASGIDriver(app=auth.router.mount())
    # Plain (non-admin) user.
    await driver.request(
        "POST",
        "/sign-up/email",
        json_body={"email": "eve@x.com", "password": "evepass1"},
    )
    r = await driver.request("GET", "/scim/v2/Users")
    assert r.status == 401
    assert r.json()["code"] == "SCIM_UNAUTHORIZED"


async def test_scim_api_key_with_scim_scope() -> None:
    import json as _json

    driver, _auth = await _admin_driver()
    # Create an api key as admin (clients may not set server-only `permissions`).
    r = await driver.request(
        "POST",
        "/api-key/create",
        json_body={"name": "scim-bot"},
    )
    assert r.status == 200
    body = r.json()
    raw = body["key"]
    # Grant the scim scope server-side (mirrors how an operator would provision it).
    await _auth.context.adapter.update(
        model="apikey",
        where=(Where(field="id", value=body["id"]),),
        update={"permissions": _json.dumps({"scim": ["read", "write"]})},
    )

    # Drop session — use only the api key header
    driver.cookies.clear()
    r = await driver.request(
        "GET", "/scim/v2/Users", headers={"authorization": f"ApiKey {raw}"}
    )
    assert r.status == 200, r.json()


async def test_scim_api_key_without_scope_rejected() -> None:
    driver, _auth = await _admin_driver()
    r = await driver.request("POST", "/api-key/create", json_body={"name": "no-scim"})
    raw = r.json()["key"]
    driver.cookies.clear()
    r = await driver.request(
        "GET", "/scim/v2/Users", headers={"authorization": f"ApiKey {raw}"}
    )
    assert r.status == 401
