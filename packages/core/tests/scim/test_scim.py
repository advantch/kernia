"""SCIM plugin tests.

Ported 1:1 (names + assertions) from the upstream vitest suites:

  * ``reference/packages/scim/src/scim.test.ts``
  * ``reference/packages/scim/src/scim-users.test.ts``
  * ``reference/packages/scim/src/scim.management.test.ts``
  * ``reference/packages/scim/src/scim-patch.test.ts`` (unit-level, see
    ``test_patch_operations.py``)

Behavioural caveats vs. upstream, documented per-assertion:

  * The Python core router always renders dict results with HTTP 200; it cannot
    emit 201/204. We therefore assert on the JSON body + the ``location``
    response header (set by the handler) rather than the numeric status. Upstream
    asserts 201 on create and 204 on patch/delete.
  * The Python ``organization`` plugin exposes neither an ``addMember`` endpoint
    nor a ``creatorRole`` option. Tests that need extra org members create the
    ``member`` rows directly via the adapter; the single test that depends on
    org ``creatorRole`` is xfailed and called out in the report.
"""

from __future__ import annotations

import base64
from urllib.parse import quote

import pytest
from kernia.auth import init
from kernia.plugins.email_password import email_and_password
from kernia.plugins.organization import organization
from kernia.types.adapter import Where
from kernia.types.init_options import KerniaOptions
from kernia_memory_adapter import memory_adapter
from kernia_scim import SCIMOptions, SCIMProvider, scim
from kernia_test_utils import ASGIDriver

USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
LIST_RESPONSE = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"
PATCH_OP = "urn:ietf:params:scim:api:messages:2.0:PatchOp"


# ---------------------------------------------------------------------------
# Test harness — one auth app, per-user drivers (separate cookie jars).
# ---------------------------------------------------------------------------


class Harness:
    def __init__(self, scim_options: SCIMOptions | None = None) -> None:
        self.db = memory_adapter()
        self.auth = init(
            KerniaOptions(
                database=self.db,
                secret="test-secret-key",
                base_url="http://localhost:3000",
                plugins=[
                    email_and_password(),
                    scim(scim_options),
                    organization(),
                ],
            )
        )
        self.app = self.auth.router.mount()
        self._default_driver: ASGIDriver | None = None

    def driver(self) -> ASGIDriver:
        return ASGIDriver(app=self.app)

    async def cookie_driver(
        self,
        email: str = "test@email.com",
        password: str = "password",
        name: str = "Test User",
    ) -> ASGIDriver:
        d = self.driver()
        await d.request(
            "POST",
            "/sign-up/email",
            json_body={"email": email, "password": password, "name": name},
        )
        # sign-up sets the session cookie on this driver's jar already.
        return d

    async def default_driver(self) -> ASGIDriver:
        """A single signed-in driver reused across token/org calls.

        Mirrors upstream, where one logged-in user issues several SCIM tokens.
        Recreating a signup with the same email would collide and drop the
        session cookie, so the authenticated driver is cached.
        """
        if self._default_driver is None:
            self._default_driver = await self.cookie_driver()
        return self._default_driver

    async def scim_token(
        self,
        provider_id: str = "the-saml-provider-1",
        organization_id: str | None = None,
        driver: ASGIDriver | None = None,
    ) -> str:
        d = driver or await self.default_driver()
        body: dict = {"providerId": provider_id}
        if organization_id is not None:
            body["organizationId"] = organization_id
        r = await d.request("POST", "/scim/generate-token", json_body=body)
        assert r.status == 200, r.json()
        return r.json()["scimToken"]

    async def register_organization(self, org: str, driver: ASGIDriver | None = None) -> dict:
        d = driver or await self.default_driver()
        r = await d.request(
            "POST",
            "/organization/create",
            json_body={"slug": f"the-{org}", "name": f"the organization {org}"},
        )
        assert r.status == 200, r.json()
        return r.json()

    async def session_user_id(self, driver: ASGIDriver) -> str:
        r = await driver.request("GET", "/get-session")
        return r.json()["user"]["id"]


def bearer(scim_token: str) -> dict[str, str]:
    return {"authorization": f"Bearer {scim_token}"}


async def create_scim_user(driver: ASGIDriver, scim_token: str, body: dict) -> object:
    return await driver.request(
        "POST", "/scim/v2/Users", json_body=body, headers=bearer(scim_token)
    )


async def patch_scim_user(
    driver: ASGIDriver, scim_token: str, user_id: str, operations: list
) -> object:
    return await driver.request(
        "PATCH",
        f"/scim/v2/Users/{user_id}",
        json_body={"schemas": [PATCH_OP], "Operations": operations},
        headers=bearer(scim_token),
    )


# ---------------------------------------------------------------------------
# scim.test.ts — discovery + create + update
# ---------------------------------------------------------------------------


async def test_should_fetch_the_service_provider_config() -> None:
    h = Harness()
    r = await h.driver().request("GET", "/scim/v2/ServiceProviderConfig")
    assert r.status == 200
    body = r.json()
    assert body["patch"] == {"supported": True}
    assert body["bulk"] == {"supported": False}
    assert body["filter"] == {"supported": True}
    assert body["changePassword"] == {"supported": False}
    assert body["sort"] == {"supported": False}
    assert body["etag"] == {"supported": False}
    assert body["meta"] == {"resourceType": "ServiceProviderConfig"}
    assert body["schemas"] == ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"]
    scheme = body["authenticationSchemes"][0]
    assert scheme["type"] == "oauthbearertoken"
    assert scheme["primary"] is True
    assert scheme["name"] == "OAuth Bearer Token"


async def test_should_fetch_the_list_of_supported_schemas() -> None:
    h = Harness()
    r = await h.driver().request("GET", "/scim/v2/Schemas")
    assert r.status == 200
    body = r.json()
    assert body["totalResults"] == 1
    assert body["itemsPerPage"] == 1
    assert body["startIndex"] == 1
    assert body["schemas"] == [LIST_RESPONSE]
    resource = body["Resources"][0]
    assert resource["id"] == USER_SCHEMA
    assert resource["name"] == "User"
    assert resource["meta"]["resourceType"] == "Schema"
    assert "/scim/v2/Schemas/" in resource["meta"]["location"]


async def test_should_fetch_a_single_resource_schema() -> None:
    h = Harness()
    r = await h.driver().request("GET", f"/scim/v2/Schemas/{USER_SCHEMA}")
    assert r.status == 200
    body = r.json()
    assert body["id"] == USER_SCHEMA
    assert body["name"] == "User"
    assert body["meta"]["resourceType"] == "Schema"


async def test_should_return_not_found_for_unsupported_schemas() -> None:
    h = Harness()
    r = await h.driver().request("GET", "/scim/v2/Schemas/unknown")
    assert r.status == 404
    assert r.json() == {
        "detail": "Schema not found",
        "schemas": [ERROR_SCHEMA],
        "status": "404",
    }


async def test_should_fetch_the_list_of_supported_resource_types() -> None:
    h = Harness()
    r = await h.driver().request("GET", "/scim/v2/ResourceTypes")
    assert r.status == 200
    body = r.json()
    assert body["totalResults"] == 1
    assert body["itemsPerPage"] == 1
    assert body["startIndex"] == 1
    assert body["schemas"] == [LIST_RESPONSE]
    resource = body["Resources"][0]
    assert resource["id"] == "User"
    assert resource["endpoint"] == "/Users"
    assert resource["schema"] == USER_SCHEMA
    assert resource["meta"]["resourceType"] == "ResourceType"


async def test_should_fetch_a_single_resource_type() -> None:
    h = Harness()
    r = await h.driver().request("GET", "/scim/v2/ResourceTypes/User")
    assert r.status == 200
    body = r.json()
    assert body["id"] == "User"
    assert body["endpoint"] == "/Users"
    assert body["schema"] == USER_SCHEMA


async def test_should_return_not_found_for_unsupported_resource_types() -> None:
    h = Harness()
    r = await h.driver().request("GET", "/scim/v2/ResourceTypes/unknown")
    assert r.status == 404
    assert r.json() == {
        "detail": "Resource type not found",
        "schemas": [ERROR_SCHEMA],
        "status": "404",
    }


async def test_should_create_a_new_user() -> None:
    h = Harness()
    token = await h.scim_token()
    r = await create_scim_user(h.driver(), token, {"userName": "the-username"})
    assert r.status == 200, r.json()
    # Upstream sets 201 + a location header; the router can't emit 201 so we
    # assert the location header (set by the handler) instead of the status.
    location = dict(r.headers).get("location")
    assert location is not None
    assert "/scim/v2/Users/" in location
    user = r.json()
    assert user["active"] is True
    assert user["displayName"] == "the-username"
    assert user["emails"] == [{"primary": True, "value": "the-username"}]
    assert user["externalId"] == "the-username"
    assert isinstance(user["id"], str)
    assert user["meta"]["resourceType"] == "User"
    assert "/scim/v2/Users/" in user["meta"]["location"]
    assert user["name"] == {"formatted": "the-username"}
    assert USER_SCHEMA in user["schemas"]
    assert user["userName"] == "the-username"


async def test_should_create_a_new_account_linked_to_an_existing_user() -> None:
    h = Harness()
    token = await h.scim_token()
    # Pre-existing user
    other = h.driver()
    await other.request(
        "POST",
        "/sign-up/email",
        json_body={
            "email": "existing@email.com",
            "password": "the password",
            "name": "existing user",
        },
    )
    r = await create_scim_user(
        h.driver(),
        token,
        {"userName": "the-username", "emails": [{"value": "existing@email.com"}]},
    )
    assert r.status == 200, r.json()
    user = r.json()
    assert user["active"] is True
    assert user["displayName"] == "existing user"
    assert user["emails"] == [{"primary": True, "value": "existing@email.com"}]
    assert user["externalId"] == "the-username"
    assert user["name"] == {"formatted": "existing user"}
    assert user["userName"] == "existing@email.com"


async def test_should_create_a_new_user_with_external_id() -> None:
    h = Harness()
    token = await h.scim_token()
    r = await create_scim_user(
        h.driver(),
        token,
        {"externalId": "external-username", "userName": "the-username"},
    )
    user = r.json()
    assert user["externalId"] == "external-username"
    assert user["displayName"] == "the-username"
    assert user["userName"] == "the-username"


async def test_should_create_a_new_user_with_name_parts() -> None:
    h = Harness()
    token = await h.scim_token()
    r = await create_scim_user(
        h.driver(),
        token,
        {"userName": "the-username", "name": {"givenName": "Juan", "familyName": "Perez"}},
    )
    user = r.json()
    assert user["displayName"] == "Juan Perez"
    assert user["name"] == {"formatted": "Juan Perez"}
    assert user["userName"] == "the-username"


async def test_should_create_a_new_user_with_formatted_name() -> None:
    h = Harness()
    token = await h.scim_token()
    r = await create_scim_user(
        h.driver(),
        token,
        {"userName": "the-username", "name": {"formatted": "Juan Perez"}},
    )
    user = r.json()
    assert user["displayName"] == "Juan Perez"
    assert user["name"] == {"formatted": "Juan Perez"}


async def test_should_create_a_new_user_with_a_primary_email() -> None:
    h = Harness()
    token = await h.scim_token()
    r = await create_scim_user(
        h.driver(),
        token,
        {
            "userName": "the-username",
            "name": {"formatted": "Juan Perez"},
            "emails": [
                {"value": "secondary-email@test.com"},
                {"value": "primary-email@test.com", "primary": True},
            ],
        },
    )
    user = r.json()
    assert user["emails"] == [{"primary": True, "value": "primary-email@test.com"}]
    assert user["userName"] == "primary-email@test.com"


async def test_should_create_a_new_user_with_the_first_non_primary_email() -> None:
    h = Harness()
    token = await h.scim_token()
    r = await create_scim_user(
        h.driver(),
        token,
        {
            "userName": "the-username",
            "name": {"formatted": "Juan Perez"},
            "emails": [
                {"value": "secondary-email@test.com"},
                {"value": "primary-email@test.com"},
            ],
        },
    )
    user = r.json()
    assert user["emails"] == [{"primary": True, "value": "secondary-email@test.com"}]
    assert user["userName"] == "secondary-email@test.com"


async def test_should_not_allow_users_with_the_same_computed_username() -> None:
    h = Harness()
    token = await h.scim_token()
    r1 = await create_scim_user(h.driver(), token, {"userName": "the-username"})
    assert r1.status == 200
    r2 = await create_scim_user(h.driver(), token, {"userName": "the-username"})
    assert r2.status == 409
    assert r2.json()["detail"] == "User already exists"


async def test_create_should_not_allow_anonymous_access() -> None:
    h = Harness()
    r = await h.driver().request("POST", "/scim/v2/Users", json_body={"userName": "the-username"})
    assert r.status == 401
    assert r.json() == {
        "detail": "SCIM token is required",
        "schemas": [ERROR_SCHEMA],
        "status": "401",
    }


async def test_should_update_an_existing_resource() -> None:
    h = Harness()
    token = await h.scim_token()
    r = await create_scim_user(
        h.driver(),
        token,
        {
            "userName": "the-username",
            "name": {"formatted": "Juan Perez"},
            "emails": [{"value": "primary-email@test.com", "primary": True}],
        },
    )
    user = r.json()
    assert user["externalId"] == "the-username"
    assert user["userName"] == "primary-email@test.com"
    assert user["name"]["formatted"] == "Juan Perez"

    r = await h.driver().request(
        "PUT",
        f"/scim/v2/Users/{user['id']}",
        json_body={
            "userName": "other-username",
            "externalId": "external-username",
            "name": {"formatted": "Daniel Lopez"},
            "emails": [{"value": "other-email@test.com"}],
        },
        headers=bearer(token),
    )
    assert r.status == 200, r.json()
    updated = r.json()
    assert updated["displayName"] == "Daniel Lopez"
    assert updated["emails"] == [{"primary": True, "value": "other-email@test.com"}]
    assert updated["externalId"] == "external-username"
    assert updated["name"] == {"formatted": "Daniel Lopez"}
    assert updated["userName"] == "other-email@test.com"


async def test_update_should_not_allow_anonymous_access() -> None:
    h = Harness()
    r = await h.driver().request(
        "PUT", "/scim/v2/Users/whatever", json_body={"userName": "the-username"}
    )
    assert r.status == 401
    assert r.json()["detail"] == "SCIM token is required"


async def test_update_should_return_not_found_for_missing_resources() -> None:
    h = Harness()
    token = await h.scim_token()
    r = await h.driver().request(
        "PUT",
        "/scim/v2/Users/missing",
        json_body={"userName": "other-username"},
        headers=bearer(token),
    )
    assert r.status == 404
    assert r.json()["detail"] == "User not found"


# ---------------------------------------------------------------------------
# scim-users.test.ts — list / get / delete / default provider
# ---------------------------------------------------------------------------


async def test_should_return_the_list_of_users() -> None:
    h = Harness()
    token = await h.scim_token()
    d = h.driver()
    user_a = (await create_scim_user(d, token, {"userName": "user-a"})).json()
    user_b = (await create_scim_user(d, token, {"userName": "user-b"})).json()

    r = await d.request("GET", "/scim/v2/Users", headers=bearer(token))
    assert r.status == 200, r.json()
    body = r.json()
    assert body["itemsPerPage"] == 2
    assert body["schemas"] == [LIST_RESPONSE]
    assert body["startIndex"] == 1
    assert body["totalResults"] == 2
    ids = {res["id"] for res in body["Resources"]}
    assert ids == {user_a["id"], user_b["id"]}


async def test_should_return_empty_list_when_no_users_provisioned() -> None:
    h = Harness()
    token = await h.scim_token()
    d = h.driver()

    r = await d.request("GET", "/scim/v2/Users", headers=bearer(token))
    body = r.json()
    assert body["itemsPerPage"] == 0
    assert body["totalResults"] == 0
    assert body["Resources"] == []

    org_a = await h.register_organization("org-a")
    org_b = await h.register_organization("org-b")
    token_a = await h.scim_token("provider-org-a", org_a["id"])
    token_b = await h.scim_token("provider-org-b", org_b["id"])

    await create_scim_user(d, token_a, {"userName": "user-a"})
    r = await d.request("GET", "/scim/v2/Users", headers=bearer(token_b))
    body = r.json()
    assert body["itemsPerPage"] == 0
    assert body["totalResults"] == 0
    assert body["Resources"] == []


async def test_list_should_only_allow_access_to_same_provider() -> None:
    h = Harness()
    token_a = await h.scim_token("provider-a")
    token_b = await h.scim_token("provider-b")
    d = h.driver()

    user_a = (await create_scim_user(d, token_b, {"userName": "user-a"})).json()
    user_b = (await create_scim_user(d, token_a, {"userName": "user-b"})).json()
    user_c = (await create_scim_user(d, token_b, {"userName": "user-c"})).json()

    ra = await d.request("GET", "/scim/v2/Users", headers=bearer(token_a))
    rb = await d.request("GET", "/scim/v2/Users", headers=bearer(token_b))

    assert ra.json()["totalResults"] == 1
    assert {res["id"] for res in ra.json()["Resources"]} == {user_b["id"]}
    assert rb.json()["totalResults"] == 2
    assert {res["id"] for res in rb.json()["Resources"]} == {
        user_a["id"],
        user_c["id"],
    }


async def test_list_should_only_allow_access_to_same_provider_and_org() -> None:
    h = Harness()
    org_a = await h.register_organization("org:a")
    org_b = await h.register_organization("org:b")
    token_a = await h.scim_token("provider-a", org_a["id"])
    token_b = await h.scim_token("provider-b", org_b["id"])
    d = h.driver()

    user_a = (await create_scim_user(d, token_b, {"userName": "user-a"})).json()
    user_b = (await create_scim_user(d, token_a, {"userName": "user-b"})).json()
    user_c = (await create_scim_user(d, token_b, {"userName": "user-c"})).json()

    ra = await d.request("GET", "/scim/v2/Users", headers=bearer(token_a))
    rb = await d.request("GET", "/scim/v2/Users", headers=bearer(token_b))

    assert ra.json()["totalResults"] == 1
    assert {res["id"] for res in ra.json()["Resources"]} == {user_b["id"]}
    assert rb.json()["totalResults"] == 2
    assert {res["id"] for res in rb.json()["Resources"]} == {
        user_a["id"],
        user_c["id"],
    }


async def test_should_filter_the_list_of_users() -> None:
    h = Harness()
    token = await h.scim_token()
    d = h.driver()
    user_a = (await create_scim_user(d, token, {"userName": "user-a"})).json()
    await create_scim_user(d, token, {"userName": "user-b"})
    await create_scim_user(d, token, {"userName": "user-c"})

    # Hoisted out of the f-string: nested same-quote + backslash inside an
    # f-string is py3.12-only syntax, and the package floor is 3.11.
    case_insensitive_filter = quote('userName eq "user-A"')
    r = await d.request(
        "GET",
        "/scim/v2/Users",
        headers=bearer(token),
        query=f"filter={case_insensitive_filter}",
    )
    assert r.status == 200, r.json()
    body = r.json()
    assert body["itemsPerPage"] == 1
    assert body["totalResults"] == 1
    assert {res["id"] for res in body["Resources"]} == {user_a["id"]}


async def test_list_should_not_allow_anonymous_access() -> None:
    h = Harness()
    r = await h.driver().request("GET", "/scim/v2/Users")
    assert r.status == 401
    assert r.json() == {
        "detail": "SCIM token is required",
        "schemas": [ERROR_SCHEMA],
        "status": "401",
    }


async def test_should_return_a_single_user_resource() -> None:
    h = Harness()
    token = await h.scim_token()
    d = h.driver()
    new_user = (await create_scim_user(d, token, {"userName": "the-username"})).json()
    r = await d.request("GET", f"/scim/v2/Users/{new_user['id']}", headers=bearer(token))
    assert r.status == 200
    assert r.json() == new_user


async def test_get_should_only_allow_access_to_same_provider() -> None:
    h = Harness()
    token_a = await h.scim_token("provider-a")
    token_b = await h.scim_token("provider-b")
    d = h.driver()

    user_a = (await create_scim_user(d, token_b, {"userName": "user-a"})).json()
    user_b = (await create_scim_user(d, token_a, {"userName": "user-b"})).json()

    r = await d.request("GET", f"/scim/v2/Users/{user_b['id']}", headers=bearer(token_a))
    assert r.json() == user_b

    r = await d.request("GET", f"/scim/v2/Users/{user_b['id']}", headers=bearer(token_b))
    assert r.status == 404
    assert r.json()["detail"] == "User not found"

    r = await d.request("GET", f"/scim/v2/Users/{user_a['id']}", headers=bearer(token_b))
    assert r.json() == user_a

    r = await d.request("GET", f"/scim/v2/Users/{user_a['id']}", headers=bearer(token_a))
    assert r.status == 404
    assert r.json()["detail"] == "User not found"


async def test_get_should_only_allow_access_to_same_provider_and_org() -> None:
    h = Harness()
    org_a = await h.register_organization("org-a")
    org_b = await h.register_organization("org-b")
    token_a = await h.scim_token("provider-a", org_a["id"])
    token_b = await h.scim_token("provider-b", org_b["id"])
    d = h.driver()

    user_a = (await create_scim_user(d, token_b, {"userName": "user-a"})).json()
    user_b = (await create_scim_user(d, token_a, {"userName": "user-b"})).json()

    r = await d.request("GET", f"/scim/v2/Users/{user_b['id']}", headers=bearer(token_a))
    assert r.json() == user_b

    r = await d.request("GET", f"/scim/v2/Users/{user_b['id']}", headers=bearer(token_b))
    assert r.status == 404

    r = await d.request("GET", f"/scim/v2/Users/{user_a['id']}", headers=bearer(token_b))
    assert r.json() == user_a

    r = await d.request("GET", f"/scim/v2/Users/{user_a['id']}", headers=bearer(token_a))
    assert r.status == 404


async def test_get_should_return_not_found_for_missing_users() -> None:
    h = Harness()
    token = await h.scim_token()
    r = await h.driver().request("GET", "/scim/v2/Users/missing", headers=bearer(token))
    assert r.status == 404
    assert r.json() == {
        "detail": "User not found",
        "schemas": [ERROR_SCHEMA],
        "status": "404",
    }


async def test_get_should_not_allow_anonymous_access() -> None:
    h = Harness()
    r = await h.driver().request("GET", "/scim/v2/Users/whatever")
    assert r.status == 401
    assert r.json()["detail"] == "SCIM token is required"


async def test_should_delete_an_existing_user() -> None:
    h = Harness()
    token = await h.scim_token()
    d = h.driver()
    new_user = (await create_scim_user(d, token, {"userName": "the-username"})).json()
    r = await d.request("DELETE", f"/scim/v2/Users/{new_user['id']}", headers=bearer(token))
    assert r.status == 200  # 204 upstream; router emits 200
    r = await d.request("GET", f"/scim/v2/Users/{new_user['id']}", headers=bearer(token))
    assert r.status == 404
    assert r.json()["detail"] == "User not found"


async def test_delete_should_not_allow_anonymous_access() -> None:
    h = Harness()
    r = await h.driver().request("DELETE", "/scim/v2/Users/whatever")
    assert r.status == 401
    assert r.json() == {
        "detail": "SCIM token is required",
        "schemas": [ERROR_SCHEMA],
        "status": "401",
    }


async def test_should_not_delete_a_missing_user() -> None:
    h = Harness()
    token = await h.scim_token()
    r = await h.driver().request("DELETE", "/scim/v2/Users/missing", headers=bearer(token))
    assert r.status == 404
    assert r.json()["detail"] == "User not found"


async def test_should_clear_secondary_storage_sessions_when_deleting_a_user() -> None:
    # Upstream wires a real secondary-storage session provider and the org
    # plugin. Two core gaps in this Python port prevent a 1:1 reproduction:
    #   1. `secondary_storage` drops the `session` table during schema
    #      resolution, but the organization plugin `extend`s `session`, which
    #      raises ValueError at init(). So the org plugin is omitted here.
    #   2. Core does not auto-persist sessions into secondary storage by token
    #      (only the custom_session provider does). So the session row is seeded
    #      into the store directly, mirroring what a provider would write.
    # What is exercised end-to-end is the SCIM-owned behavior under test:
    # deleting a SCIM user clears that user's tokens from secondary storage.
    store: dict[str, str] = {}

    class _Secondary:
        def set(self, key: str, value: str, ttl: int | None = None) -> None:
            store[key] = value

        def get(self, key: str) -> str | None:
            return store.get(key)

        def delete(self, key: str) -> None:
            store.pop(key, None)

    db = memory_adapter()
    auth = init(
        KerniaOptions(
            database=db,
            secret="test-secret-key",
            base_url="http://localhost:3000",
            secondary_storage=_Secondary(),
            plugins=[email_and_password(), scim()],
        )
    )
    app = auth.router.mount()

    admin = ASGIDriver(app=app)
    await admin.request(
        "POST",
        "/sign-up/email",
        json_body={
            "email": "scim-admin@test.com",
            "password": "password",
            "name": "SCIM Admin",
        },
    )
    r = await admin.request(
        "POST", "/scim/generate-token", json_body={"providerId": "the-saml-provider-1"}
    )
    token = r.json()["scimToken"]

    victim = ASGIDriver(app=app)
    await victim.request(
        "POST",
        "/sign-up/email",
        json_body={
            "email": "scim-victim@test.com",
            "password": "password",
            "name": "SCIM Victim",
        },
    )
    created = await admin.request(
        "POST",
        "/scim/v2/Users",
        json_body={"userName": "scim-victim@test.com"},
        headers=bearer(token),
    )
    victim_id = created.json()["id"]

    rows = await db.find_many(model="session", where=(Where(field="userId", value=victim_id),))
    victim_token = rows[0]["token"]
    # Seed secondary storage as a session provider would (see note above).
    store[victim_token] = victim_id
    assert victim_token in store

    await admin.request("DELETE", f"/scim/v2/Users/{victim_id}", headers=bearer(token))
    assert victim_token not in store


async def test_should_work_with_a_default_scim_provider() -> None:
    # base64url("the-scim-token:the-scim-provider")
    scim_token = base64.urlsafe_b64encode(b"the-scim-token:the-scim-provider").rstrip(b"=").decode()
    h = Harness(
        SCIMOptions(
            default_scim=(
                SCIMProvider(provider_id="the-scim-provider", scim_token="the-scim-token"),
            )
        )
    )
    d = h.driver()
    created = (await create_scim_user(d, scim_token, {"userName": "the-username"})).json()
    assert created["id"]

    r = await d.request("GET", f"/scim/v2/Users/{created['id']}", headers=bearer(scim_token))
    assert r.json() == created

    r = await d.request("GET", "/scim/v2/Users", headers=bearer(scim_token))
    assert r.json()["Resources"] == [created]

    r = await d.request(
        "PUT",
        f"/scim/v2/Users/{created['id']}",
        json_body={"userName": "new-username"},
        headers=bearer(scim_token),
    )
    assert r.json()["userName"] == "new-username"

    r = await d.request("DELETE", f"/scim/v2/Users/{created['id']}", headers=bearer(scim_token))
    assert r.status == 200


async def test_default_provider_should_reject_invalid_scim_tokens() -> None:
    h = Harness(
        SCIMOptions(
            default_scim=(
                SCIMProvider(provider_id="the-scim-provider", scim_token="the-scim-token"),
            )
        )
    )
    r = await h.driver().request(
        "POST",
        "/scim/v2/Users",
        json_body={"userName": "the-username"},
        headers=bearer("invalid-scim-token"),
    )
    assert r.status == 401
    assert r.json()["detail"] == "Invalid SCIM token"


# ---------------------------------------------------------------------------
# scim.management.test.ts — token generation + provider connection management
# ---------------------------------------------------------------------------


async def test_generate_token_should_require_user_session() -> None:
    h = Harness()
    r = await h.driver().request("POST", "/scim/generate-token", json_body={"providerId": "the id"})
    assert r.status == 401


async def test_generate_should_fail_if_user_not_in_org() -> None:
    h = Harness()
    d = await h.cookie_driver()
    r = await d.request(
        "POST",
        "/scim/generate-token",
        json_body={"providerId": "the id", "organizationId": "the-org"},
    )
    assert r.status == 403
    assert r.json()["message"] == "You are not a member of the organization"


async def test_generate_should_fail_on_invalid_provider() -> None:
    h = Harness(SCIMOptions(store_scim_token="plain"))
    d = await h.cookie_driver()
    r = await d.request("POST", "/scim/generate-token", json_body={"providerId": "the:provider"})
    assert r.status == 400
    assert r.json()["message"] == "Provider id contains forbidden characters"


async def test_rejects_provider_ids_colliding_with_builtin_account_providers() -> None:
    h = Harness()
    d = await h.cookie_driver()
    for reserved in (
        "credential",
        "email-otp",
        "magic-link",
        "phone-number",
        "anonymous",
        "siwe",
    ):
        r = await d.request("POST", "/scim/generate-token", json_body={"providerId": reserved})
        assert r.status == 400
        assert (
            r.json()["message"]
            == "Provider id collides with a built-in account provider and cannot be used for SCIM"
        )


async def test_rejects_provider_ids_colliding_with_social_providers() -> None:
    from kernia.social_providers import google

    db = memory_adapter()
    auth = init(
        KerniaOptions(
            database=db,
            secret="test-secret-key",
            base_url="http://localhost:3000",
            social_providers={
                "google": google(
                    client_id="google-client-id",
                    client_secret="google-client-secret",
                )
            },
            plugins=[email_and_password(), scim()],
        )
    )
    app = auth.router.mount()
    d = ASGIDriver(app=app)
    await d.request(
        "POST",
        "/sign-up/email",
        json_body={
            "email": "social@email.com",
            "password": "password",
            "name": "Social User",
        },
    )
    r = await d.request("POST", "/scim/generate-token", json_body={"providerId": "google"})
    assert r.status == 400
    assert (
        r.json()["message"]
        == "Provider id collides with a built-in account provider and cannot be used for SCIM"
    )


async def test_should_generate_a_new_scim_token_plain() -> None:
    h = Harness(SCIMOptions(store_scim_token="plain"))
    d = await h.cookie_driver()
    r = await d.request("POST", "/scim/generate-token", json_body={"providerId": "the id"})
    assert r.status == 200
    token = r.json()["scimToken"]
    assert isinstance(token, str)
    created = await create_scim_user(h.driver(), token, {"userName": "the-username"})
    assert created.status == 200, created.json()


async def test_should_generate_a_new_scim_token_hashed() -> None:
    h = Harness(SCIMOptions(store_scim_token="hashed"))
    d = await h.cookie_driver()
    r = await d.request("POST", "/scim/generate-token", json_body={"providerId": "the id"})
    token = r.json()["scimToken"]
    created = await create_scim_user(h.driver(), token, {"userName": "the-username"})
    assert created.status == 200, created.json()


async def test_should_generate_a_new_scim_token_custom_hash() -> None:
    h = Harness(SCIMOptions(store_scim_token={"hash": lambda v: v + "hello"}))
    d = await h.cookie_driver()
    r = await d.request("POST", "/scim/generate-token", json_body={"providerId": "the id"})
    token = r.json()["scimToken"]
    created = await create_scim_user(h.driver(), token, {"userName": "the-username"})
    assert created.status == 200, created.json()


async def test_should_generate_a_new_scim_token_encrypted() -> None:
    h = Harness(SCIMOptions(store_scim_token="encrypted"))
    d = await h.cookie_driver()
    r = await d.request("POST", "/scim/generate-token", json_body={"providerId": "the id"})
    token = r.json()["scimToken"]
    created = await create_scim_user(h.driver(), token, {"userName": "the-username"})
    assert created.status == 200, created.json()


async def test_should_generate_a_new_scim_token_custom_encryption() -> None:
    h = Harness(SCIMOptions(store_scim_token={"encrypt": lambda v: v, "decrypt": lambda v: v}))
    d = await h.cookie_driver()
    r = await d.request("POST", "/scim/generate-token", json_body={"providerId": "the id"})
    token = r.json()["scimToken"]
    created = await create_scim_user(h.driver(), token, {"userName": "the-username"})
    assert created.status == 200, created.json()


async def test_should_generate_a_new_scim_token_associated_to_an_org() -> None:
    h = Harness()
    d = await h.cookie_driver()
    org = await h.register_organization("org-a", driver=d)
    r = await d.request(
        "POST",
        "/scim/generate-token",
        json_body={"providerId": "the id", "organizationId": org["id"]},
    )
    assert r.status == 200
    assert isinstance(r.json()["scimToken"], str)


async def test_should_execute_hooks_before_scim_token_generation() -> None:
    def before(payload: dict) -> None:
        member = payload.get("member")
        if member and member.get("role") == "owner":
            raise _Forbidden("You do not have enough privileges to generate a SCIM token")

    from kernia.error import APIError

    class _Forbidden(APIError):
        def __init__(self, message: str) -> None:
            super().__init__(403, "FORBIDDEN", message=message)

    h = Harness(SCIMOptions(before_scim_token_generated=before))
    d = await h.cookie_driver()
    org = await h.register_organization("the org", driver=d)
    r = await d.request(
        "POST",
        "/scim/generate-token",
        json_body={"providerId": "the id", "organizationId": org["id"]},
    )
    assert r.status == 403
    assert r.json()["message"] == "You do not have enough privileges to generate a SCIM token"


async def test_should_execute_hooks_after_scim_token_generation() -> None:
    seen: dict = {}

    def after(payload: dict) -> None:
        seen["scimToken"] = payload["scimProvider"]["scimToken"]

    h = Harness(SCIMOptions(store_scim_token="plain", after_scim_token_generated=after))
    d = await h.cookie_driver()
    r = await d.request("POST", "/scim/generate-token", json_body={"providerId": "the id"})
    assert r.status == 200
    assert isinstance(r.json()["scimToken"], str)
    assert isinstance(seen["scimToken"], str)


async def test_should_deny_regenerate_when_not_owner_of_personal_provider() -> None:
    h = Harness(SCIMOptions(provider_ownership=_ownership_on()))
    da = await h.cookie_driver("user1@policy.test", "password", "User One")
    db_ = await h.cookie_driver("user2@policy.test", "password", "User Two")

    r = await da.request(
        "POST", "/scim/generate-token", json_body={"providerId": "user-a-owned-provider"}
    )
    assert r.status == 200
    r = await db_.request(
        "POST", "/scim/generate-token", json_body={"providerId": "user-a-owned-provider"}
    )
    assert r.status == 403
    assert r.json()["message"] == "You must be the owner to access this provider"


async def test_should_deny_regenerate_when_provider_belongs_to_another_org() -> None:
    h = Harness()
    d1 = await h.cookie_driver("user1@policy.test", "password", "User One")
    d2 = await h.cookie_driver("user2@policy.test", "password", "User Two")
    org1 = await h.register_organization("policy-org-1", driver=d1)
    await h.register_organization("policy-org-2", driver=d2)

    r = await d1.request(
        "POST",
        "/scim/generate-token",
        json_body={"providerId": "other-org", "organizationId": org1["id"]},
    )
    assert r.status == 200

    r = await d2.request("POST", "/scim/generate-token", json_body={"providerId": "other-org"})
    assert r.status == 403
    assert r.json()["message"] == "You must be a member of the organization to access this provider"


# -- list-provider-connections ------------------------------------------------


async def test_list_connections_empty_when_not_in_any_org() -> None:
    h = Harness()
    d = await h.cookie_driver()
    r = await d.request("GET", "/scim/list-provider-connections")
    assert r.status == 200
    assert r.json() == {"providers": []}


async def test_list_connections_returns_org_scoped_providers() -> None:
    h = Harness()
    da = await h.cookie_driver("user1@policy.test", "password", "User One")
    db_ = await h.cookie_driver("user2@policy.test", "password", "User Two")
    org_a = await h.register_organization("org-a", driver=da)
    org_b = await h.register_organization("org-b", driver=db_)

    await h.scim_token("provider-1", org_a["id"], driver=da)
    await h.scim_token("provider-2", org_a["id"], driver=da)
    await h.scim_token("provider-3", org_b["id"], driver=db_)

    r = await da.request("GET", "/scim/list-provider-connections")
    providers = r.json()["providers"]
    assert len(providers) == 2
    by_id = {p["providerId"]: p for p in providers}
    assert sorted(by_id) == ["provider-1", "provider-2"]
    assert by_id["provider-1"]["organizationId"] == org_a["id"]
    assert by_id["provider-2"]["organizationId"] == org_a["id"]


async def test_list_connections_returns_owned_non_org_providers() -> None:
    h = Harness(SCIMOptions(provider_ownership=_ownership_on()))
    da = await h.cookie_driver("user1@policy.test", "password", "User One")
    db_ = await h.cookie_driver("user2@policy.test", "password", "User Two")

    await da.request(
        "POST",
        "/scim/generate-token",
        json_body={"providerId": "user-a-personal-provider"},
    )

    r = await da.request("GET", "/scim/list-provider-connections")
    providers = r.json()["providers"]
    assert len(providers) == 1
    assert providers[0]["providerId"] == "user-a-personal-provider"
    assert providers[0]["organizationId"] is None

    r = await db_.request("GET", "/scim/list-provider-connections")
    assert len(r.json()["providers"]) == 0


# -- get-provider-connection --------------------------------------------------


async def test_get_connection_returns_details_when_org_member() -> None:
    h = Harness()
    d = await h.cookie_driver()
    org = await h.register_organization("scim-get-org", driver=d)
    await h.scim_token("my-provider", org["id"], driver=d)

    r = await d.request("GET", "/scim/get-provider-connection", query="providerId=my-provider")
    assert r.status == 200
    assert r.json()["providerId"] == "my-provider"
    assert r.json()["organizationId"] == org["id"]


async def test_get_connection_returns_own_non_org_provider() -> None:
    h = Harness()
    d = await h.cookie_driver()
    await h.scim_token("no-org-provider", driver=d)
    r = await d.request("GET", "/scim/get-provider-connection", query="providerId=no-org-provider")
    assert r.status == 200
    assert r.json()["providerId"] == "no-org-provider"
    assert r.json()["organizationId"] is None


async def test_get_connection_denies_non_owner_of_non_org_provider() -> None:
    h = Harness(SCIMOptions(provider_ownership=_ownership_on()))
    da = await h.cookie_driver("user1@policy.test", "password", "User One")
    db_ = await h.cookie_driver("user2@policy.test", "password", "User Two")
    await da.request(
        "POST", "/scim/generate-token", json_body={"providerId": "user-a-owned-provider"}
    )
    r = await db_.request(
        "GET",
        "/scim/get-provider-connection",
        query="providerId=user-a-owned-provider",
    )
    assert r.status == 403
    assert r.json()["message"] == "You must be the owner to access this provider"


async def test_get_connection_403_when_provider_belongs_to_another_org() -> None:
    h = Harness()
    d1 = await h.cookie_driver("user1@policy.test", "password", "User One")
    d2 = await h.cookie_driver("user2@policy.test", "password", "User Two")
    org1 = await h.register_organization("get-policy-org-1", driver=d1)
    await h.register_organization("get-policy-org-2", driver=d2)
    await d1.request(
        "POST",
        "/scim/generate-token",
        json_body={"providerId": "other-org-provider", "organizationId": org1["id"]},
    )
    r = await d2.request(
        "GET",
        "/scim/get-provider-connection",
        query="providerId=other-org-provider",
    )
    assert r.status == 403
    assert r.json()["message"] == "You must be a member of the organization to access this provider"


async def test_get_connection_403_when_creator_removed_from_org() -> None:
    # Upstream uses addMember/removeMember (not exposed by the Python org plugin);
    # we manipulate the member rows directly via the adapter to reproduce the
    # same state: token creator (user A) is no longer a member of the org.
    h = Harness()
    da = await h.cookie_driver("user1@policy.test", "password", "User One")
    org = await h.register_organization("owner-removed-org", driver=da)
    await da.request(
        "POST",
        "/scim/generate-token",
        json_body={
            "providerId": "owner-removed-provider",
            "organizationId": org["id"],
        },
    )
    user_a_id = await h.session_user_id(da)
    await h.db.delete_many(
        model="member",
        where=(
            Where(field="organizationId", value=org["id"]),
            Where(field="userId", value=user_a_id),
        ),
    )

    r = await da.request(
        "GET",
        "/scim/get-provider-connection",
        query="providerId=owner-removed-provider",
    )
    assert r.status == 403
    assert r.json()["message"] == "You must be a member of the organization to access this provider"

    r = await da.request("GET", "/scim/list-provider-connections")
    assert not any(p["providerId"] == "owner-removed-provider" for p in r.json()["providers"])


async def test_get_connection_404_for_unknown_provider_id() -> None:
    h = Harness()
    d = await h.cookie_driver()
    r = await d.request("GET", "/scim/get-provider-connection", query="providerId=unknown")
    assert r.status == 404
    assert r.json()["message"] == "SCIM provider not found"


# -- delete-provider-connection -----------------------------------------------


async def test_delete_connection_org_scoped_and_invalidates_token() -> None:
    h = Harness()
    d = await h.cookie_driver()
    org = await h.register_organization("org-a", driver=d)
    token = await h.scim_token("my-provider", org["id"], driver=d)

    before = await d.request("GET", "/scim/list-provider-connections")
    assert any(p["providerId"] == "my-provider" for p in before.json()["providers"])

    r = await d.request(
        "POST", "/scim/delete-provider-connection", json_body={"providerId": "my-provider"}
    )
    assert r.json() == {"success": True}

    after = await d.request("GET", "/scim/list-provider-connections")
    assert not any(p["providerId"] == "my-provider" for p in after.json()["providers"])

    # token is now invalid
    r = await h.driver().request("GET", "/scim/v2/Users/any", headers=bearer(token))
    assert r.status == 401


async def test_delete_connection_403_when_provider_belongs_to_another_org() -> None:
    h = Harness()
    d1 = await h.cookie_driver("user1@policy.test", "password", "User One")
    d2 = await h.cookie_driver("user2@policy.test", "password", "User Two")
    org1 = await h.register_organization("del-policy-org-1", driver=d1)
    await h.register_organization("del-policy-org-2", driver=d2)
    await d1.request(
        "POST",
        "/scim/generate-token",
        json_body={"providerId": "other-org-del", "organizationId": org1["id"]},
    )
    r = await d2.request(
        "POST",
        "/scim/delete-provider-connection",
        json_body={"providerId": "other-org-del"},
    )
    assert r.status == 403
    assert r.json()["message"] == "You must be a member of the organization to access this provider"


async def test_delete_connection_404_for_unknown_provider_id() -> None:
    h = Harness()
    d = await h.cookie_driver()
    r = await d.request(
        "POST", "/scim/delete-provider-connection", json_body={"providerId": "unknown"}
    )
    assert r.status == 404
    assert r.json()["message"] == "SCIM provider not found"


async def test_delete_connection_denies_non_owner_of_non_org_provider() -> None:
    h = Harness(SCIMOptions(provider_ownership=_ownership_on()))
    da = await h.cookie_driver("user1@policy.test", "password", "User One")
    db_ = await h.cookie_driver("user2@policy.test", "password", "User Two")
    await da.request(
        "POST", "/scim/generate-token", json_body={"providerId": "user-a-delete-provider"}
    )
    r = await db_.request(
        "POST",
        "/scim/delete-provider-connection",
        json_body={"providerId": "user-a-delete-provider"},
    )
    assert r.status == 403
    assert r.json()["message"] == "You must be the owner to access this provider"


# -- role-based authorization -------------------------------------------------


async def _add_member(h: Harness, org_id: str, user_id: str, role: str | list[str]) -> None:
    role_str = ",".join(role) if isinstance(role, list) else role
    await h.db.create(
        model="member",
        data={"organizationId": org_id, "userId": user_id, "role": role_str},
    )


async def test_should_deny_org_scoped_token_for_regular_member() -> None:
    h = Harness()
    owner = await h.cookie_driver("user1@policy.test", "password", "User One")
    member = await h.cookie_driver("user2@policy.test", "password", "User Two")
    org = await h.register_organization("role-test-org", driver=owner)
    await _add_member(h, org["id"], await h.session_user_id(member), "member")

    r = await member.request(
        "POST",
        "/scim/generate-token",
        json_body={"providerId": "member-attempt", "organizationId": org["id"]},
    )
    assert r.status == 403
    assert r.json()["message"] == "Insufficient role for this operation"


async def test_should_allow_org_scoped_token_for_an_admin() -> None:
    h = Harness()
    owner = await h.cookie_driver("user1@policy.test", "password", "User One")
    admin_d = await h.cookie_driver("user2@policy.test", "password", "User Two")
    org = await h.register_organization("admin-test-org", driver=owner)
    await _add_member(h, org["id"], await h.session_user_id(admin_d), "admin")

    r = await admin_d.request(
        "POST",
        "/scim/generate-token",
        json_body={"providerId": "admin-attempt", "organizationId": org["id"]},
    )
    assert r.status == 200
    assert isinstance(r.json()["scimToken"], str)


async def test_should_allow_org_provider_access_for_multiple_roles() -> None:
    h = Harness()
    owner = await h.cookie_driver("user1@policy.test", "password", "User One")
    member = await h.cookie_driver("user2@policy.test", "password", "User Two")
    org = await h.register_organization("multi-role-org", driver=owner)
    await _add_member(h, org["id"], await h.session_user_id(member), ["member", "admin"])

    r = await member.request(
        "POST",
        "/scim/generate-token",
        json_body={"providerId": "multi-role-provider", "organizationId": org["id"]},
    )
    assert r.status == 200

    r = await member.request("GET", "/scim/list-provider-connections")
    assert any(p["providerId"] == "multi-role-provider" for p in r.json()["providers"])

    r = await member.request(
        "GET",
        "/scim/get-provider-connection",
        query="providerId=multi-role-provider",
    )
    assert r.json()["providerId"] == "multi-role-provider"
    assert r.json()["organizationId"] == org["id"]


async def test_should_respect_custom_required_role_configuration() -> None:
    h = Harness(SCIMOptions(required_role=("owner",)))
    owner = await h.cookie_driver("user1@policy.test", "password", "User One")
    admin_d = await h.cookie_driver("user2@policy.test", "password", "User Two")
    org = await h.register_organization("custom-role-org", driver=owner)
    await _add_member(h, org["id"], await h.session_user_id(admin_d), "admin")

    r = await admin_d.request(
        "POST",
        "/scim/generate-token",
        json_body={"providerId": "custom-role-attempt", "organizationId": org["id"]},
    )
    assert r.status == 403
    assert r.json()["message"] == "Insufficient role for this operation"

    r = await owner.request(
        "POST",
        "/scim/generate-token",
        json_body={"providerId": "custom-role-attempt", "organizationId": org["id"]},
    )
    assert r.status == 200


@pytest.mark.xfail(
    reason=(
        "Python organization plugin exposes no creatorRole option, so the SCIM "
        "default required-role set cannot pick it up. Upstream parity gap in the "
        "organization plugin, not the SCIM plugin."
    ),
    strict=True,
)
async def test_should_default_to_org_creator_role_when_customized() -> None:
    h = Harness()  # cannot pass organization(creatorRole="super-admin")
    creator = await h.cookie_driver("user1@policy.test", "password", "User One")
    org = await h.register_organization("custom-creator-role", driver=creator)
    # The org creator is assigned role "owner" by the Python org plugin, so a
    # requiredRole derived from a custom creatorRole ("super-admin") would reject
    # them. This asserts the customized creatorRole flow that Python lacks.
    await h.db.update(
        model="member",
        where=(
            Where(field="organizationId", value=org["id"]),
            Where(field="userId", value=await h.session_user_id(creator)),
        ),
        update={"role": "super-admin"},
    )
    h2 = Harness(SCIMOptions(creator_role="super-admin"))
    # Different harness/db: this can never line up — documents the gap.
    r = await creator.request(
        "POST",
        "/scim/generate-token",
        json_body={"providerId": "custom-creator-role-provider", "organizationId": org["id"]},
    )
    assert r.status == 200
    assert h2 is not None


async def test_should_filter_org_providers_by_role_in_list_endpoint() -> None:
    h = Harness()
    owner = await h.cookie_driver("user1@policy.test", "password", "User One")
    member = await h.cookie_driver("user2@policy.test", "password", "User Two")
    org = await h.register_organization("list-role-org", driver=owner)
    await _add_member(h, org["id"], await h.session_user_id(member), "member")

    await owner.request(
        "POST",
        "/scim/generate-token",
        json_body={"providerId": "list-role-provider", "organizationId": org["id"]},
    )

    r = await owner.request("GET", "/scim/list-provider-connections")
    assert any(p["providerId"] == "list-role-provider" for p in r.json()["providers"])

    r = await member.request("GET", "/scim/list-provider-connections")
    assert not any(p["providerId"] == "list-role-provider" for p in r.json()["providers"])


def _ownership_on():
    from kernia_scim.types import ProviderOwnership

    return ProviderOwnership(enabled=True)


# ---------------------------------------------------------------------------
# scim-patch.test.ts — PATCH /scim/v2/Users
# ---------------------------------------------------------------------------


async def _create_patch_user(h: Harness, body: dict) -> tuple[ASGIDriver, str, dict]:
    token = await h.scim_token()
    d = h.driver()
    created = (await create_scim_user(d, token, body)).json()
    return d, token, created


@pytest.mark.parametrize("op", ["replace", "add"])
async def test_should_partially_update_a_user_resource(op: str) -> None:
    h = Harness()
    d, token, user = await _create_patch_user(
        h,
        {
            "userName": "the-username",
            "name": {"formatted": "Juan Perez"},
            "emails": [{"value": "primary-email@test.com", "primary": True}],
        },
    )
    assert user["externalId"] == "the-username"
    assert user["userName"] == "primary-email@test.com"
    assert user["name"]["formatted"] == "Juan Perez"
    assert user["emails"][0]["value"] == "primary-email@test.com"

    r = await patch_scim_user(
        d,
        token,
        user["id"],
        [
            {"op": op, "path": "/externalId", "value": "external-username"},
            {"op": op, "path": "/userName", "value": "other-username"},
            {"op": op, "path": "/name/givenName", "value": "Daniel"},
        ],
    )
    assert r.status == 200, r.json()  # 204 upstream; router emits 200

    updated = (await d.request("GET", f"/scim/v2/Users/{user['id']}", headers=bearer(token))).json()
    assert updated["active"] is True
    assert updated["displayName"] == "Daniel Perez"
    assert updated["emails"] == [{"primary": True, "value": "other-username"}]
    assert updated["externalId"] == "external-username"
    assert updated["name"] == {"formatted": "Daniel Perez"}
    assert updated["userName"] == "other-username"
    assert USER_SCHEMA in updated["schemas"]
    assert "/scim/v2/Users/" in updated["meta"]["location"]
    assert updated["meta"]["resourceType"] == "User"


async def test_should_partially_update_with_mixed_operations() -> None:
    h = Harness()
    d, token, user = await _create_patch_user(
        h,
        {
            "userName": "the-username",
            "name": {"formatted": "Juan Perez"},
            "emails": [{"value": "primary-email@test.com", "primary": True}],
        },
    )
    await patch_scim_user(
        d,
        token,
        user["id"],
        [
            {"op": "add", "path": "/externalId", "value": "external-username"},
            {"op": "replace", "path": "/userName", "value": "other-username"},
            {"op": "add", "path": "/name/formatted", "value": "Daniel Lopez"},
        ],
    )
    updated = (await d.request("GET", f"/scim/v2/Users/{user['id']}", headers=bearer(token))).json()
    assert updated["displayName"] == "Daniel Lopez"
    assert updated["emails"] == [{"primary": True, "value": "other-username"}]
    assert updated["externalId"] == "external-username"
    assert updated["name"] == {"formatted": "Daniel Lopez"}
    assert updated["userName"] == "other-username"


@pytest.mark.parametrize("op", ["replace", "add"])
async def test_should_partially_update_multiple_name_sub_attributes(op: str) -> None:
    h = Harness()
    d, token, user = await _create_patch_user(
        h, {"userName": "sub-attribute-test-user", "name": {"formatted": "Original Name"}}
    )
    await patch_scim_user(
        d,
        token,
        user["id"],
        [
            {"op": op, "path": "/name/givenName", "value": "Updated"},
            {"op": op, "path": "/name/familyName", "value": "Value"},
        ],
    )
    updated = (await d.request("GET", f"/scim/v2/Users/{user['id']}", headers=bearer(token))).json()
    assert updated["name"]["formatted"] == "Updated Value"


@pytest.mark.parametrize("op", ["replace", "add"])
async def test_should_update_nested_object_values_with_path_prefix(op: str) -> None:
    h = Harness()
    d, token, user = await _create_patch_user(
        h, {"userName": "nested-test-user", "name": {"formatted": "Original Name"}}
    )
    await patch_scim_user(
        d,
        token,
        user["id"],
        [
            {"op": op, "path": "name", "value": {"givenName": "Nested"}},
            {"op": op, "path": "name", "value": {"familyName": "User"}},
            {"op": op, "path": "userName", "value": "nested-test-user-updated"},
        ],
    )
    updated = (await d.request("GET", f"/scim/v2/Users/{user['id']}", headers=bearer(token))).json()
    assert updated["name"]["formatted"] == "Nested User"
    assert updated["displayName"] == "Nested User"
    assert updated["userName"] == "nested-test-user-updated"


@pytest.mark.parametrize("op", ["replace", "add"])
async def test_should_support_operations_without_explicit_path(op: str) -> None:
    h = Harness()
    d, token, user = await _create_patch_user(h, {"userName": "no-path-test-user"})
    await patch_scim_user(
        d,
        token,
        user["id"],
        [
            {
                "op": op,
                "value": {
                    "name": {"formatted": "No Path Name"},
                    "userName": "Username",
                },
            }
        ],
    )
    updated = (await d.request("GET", f"/scim/v2/Users/{user['id']}", headers=bearer(token))).json()
    assert updated["name"]["formatted"] == "No Path Name"
    assert updated["userName"] == "username"


async def test_should_support_dot_notation_in_paths() -> None:
    h = Harness()
    d, token, user = await _create_patch_user(
        h, {"userName": "dot-notation-user", "name": {"formatted": "Original Name"}}
    )
    await patch_scim_user(
        d,
        token,
        user["id"],
        [
            {"op": "replace", "path": "name.familyName", "value": "Dot"},
            {"op": "add", "path": "name.givenName", "value": "User"},
            {"op": "add", "path": "userName", "value": "Username"},
        ],
    )
    updated = (await d.request("GET", f"/scim/v2/Users/{user['id']}", headers=bearer(token))).json()
    assert updated["name"]["formatted"] == "User Dot"
    assert updated["userName"] == "username"


@pytest.mark.parametrize("op", ["replace", "add"])
async def test_should_handle_operation_case_insensitively(op: str) -> None:
    h = Harness()
    d, token, user = await _create_patch_user(
        h, {"userName": "user-case-insensitive", "name": {"formatted": "Original"}}
    )
    await patch_scim_user(
        d,
        token,
        user["id"],
        [{"op": op.upper(), "path": "name.formatted", "value": "user-case"}],
    )
    updated = (await d.request("GET", f"/scim/v2/Users/{user['id']}", headers=bearer(token))).json()
    assert updated["name"]["formatted"] == "user-case"


async def test_should_skip_add_operation_when_value_already_exists() -> None:
    h = Harness()
    d, token, user = await _create_patch_user(
        h, {"userName": "add-same-info-user", "name": {"formatted": "Existing Name"}}
    )
    r = await patch_scim_user(
        d,
        token,
        user["id"],
        [{"op": "add", "path": "/name/formatted", "value": "Existing Name"}],
    )
    assert r.status == 400
    assert r.json() == {
        "detail": "No valid fields to update",
        "schemas": [ERROR_SCHEMA],
        "status": "400",
    }


@pytest.mark.parametrize("op", ["replace", "add"])
async def test_patch_should_ignore_op_on_non_existing_path(op: str) -> None:
    h = Harness()
    d, token, user = await _create_patch_user(
        h, {"userName": "non-existing-path", "name": {"formatted": "Original Name"}}
    )
    r = await patch_scim_user(
        d, token, user["id"], [{"op": op, "path": "/nonExistentField", "value": "X"}]
    )
    assert r.status == 400
    assert r.json() == {
        "detail": "No valid fields to update",
        "schemas": [ERROR_SCHEMA],
        "status": "400",
    }


async def test_patch_should_ignore_non_existing_operation() -> None:
    h = Harness()
    d, token, user = await _create_patch_user(h, {"userName": "non-existing-operation"})
    r = await patch_scim_user(
        d, token, user["id"], [{"op": "update", "path": "userName", "value": "X"}]
    )
    assert r.status == 400
    assert r.json() == {
        "code": "VALIDATION_ERROR",
        "message": (
            '[body.Operations.0.op] Invalid option: expected one of "replace"|"add"|"remove"'
        ),
    }


async def test_patch_should_return_not_found_for_missing_users() -> None:
    h = Harness()
    token = await h.scim_token()
    r = await patch_scim_user(
        h.driver(),
        token,
        "missing",
        [{"op": "replace", "path": "/externalId", "value": "external-username"}],
    )
    assert r.status == 404
    assert r.json() == {
        "detail": "User not found",
        "schemas": [ERROR_SCHEMA],
        "status": "404",
    }


async def test_patch_should_fail_on_invalid_updates() -> None:
    h = Harness()
    d, token, user = await _create_patch_user(h, {"userName": "the-username"})
    r = await patch_scim_user(d, token, user["id"], [])
    assert r.status == 400
    assert r.json() == {
        "detail": "No valid fields to update",
        "schemas": [ERROR_SCHEMA],
        "status": "400",
    }


async def test_patch_should_not_allow_anonymous_access() -> None:
    h = Harness()
    r = await h.driver().request(
        "PATCH",
        "/scim/v2/Users/missing",
        json_body={
            "schemas": [PATCH_OP],
            "Operations": [{"op": "replace", "path": "/externalId", "value": "external-username"}],
        },
    )
    assert r.status == 401
    assert r.json() == {
        "detail": "SCIM token is required",
        "schemas": [ERROR_SCHEMA],
        "status": "401",
    }
