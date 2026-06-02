"""Ported from reference/packages/oauth-provider/src/register.test.ts.

The Python port's DCR endpoint (`/oauth2/register`) does not gate on a user
session and has no organization/clientReference/metadata-spread machinery, so
the session-auth, organization, skip_consent, and metadata cases are not
portable (see skips). The RFC 7591 validation behaviors (response_types,
public/confidential type consistency, secret/id overwrite) are ported.
"""

from __future__ import annotations

import pytest
from kernia_test_utils import ASGIDriver

from .conftest import REDIRECT_URI, make_auth


@pytest.fixture
async def driver():
    auth = make_auth(
        supported_scopes=(
            "openid",
            "profile",
            "email",
            "offline_access",
            "create:test",
            "delete:test",
        )
    )
    return ASGIDriver(app=auth.router.mount())


async def _register(driver, **body):
    body.setdefault("name", "App")
    body.setdefault("redirect_uris", [REDIRECT_URI])
    return await driver.request("POST", "/oauth2/register", json_body=body)


async def test_fail_without_body(driver) -> None:
    # Missing the required client metadata (redirect_uris) is a 400.
    r = await driver.request("POST", "/oauth2/register", json_body={})
    assert r.status == 400


async def test_register_private_client_minimum(driver) -> None:
    r = await _register(driver)
    assert r.status == 200, r.json()
    assert r.json()["client_id"]
    assert r.json()["client_secret"]


async def test_fail_response_type_not_code(driver) -> None:
    r = await _register(driver, response_types=["token"])
    assert r.status == 400


async def test_fail_public_client_with_web_type(driver) -> None:
    r = await _register(driver, token_endpoint_auth_method="none", type="web")
    assert r.status == 400


@pytest.mark.parametrize("client_type", ["native", "user-agent-based"])
async def test_fail_confidential_client_with_public_type(driver, client_type) -> None:
    r = await _register(
        driver, token_endpoint_auth_method="client_secret_post", type=client_type
    )
    assert r.status == 400


@pytest.mark.parametrize("client_type", ["native", "user-agent-based"])
async def test_register_public_client(driver, client_type) -> None:
    r = await _register(driver, token_endpoint_auth_method="none", type=client_type)
    assert r.status == 200, r.json()
    assert r.json()["client_id"]
    # Public clients get no usable secret.
    assert not r.json()["client_secret"]


async def test_confidential_method_and_type_preserved(driver) -> None:
    r = await _register(
        driver, token_endpoint_auth_method="client_secret_post", type="web"
    )
    assert r.status == 200, r.json()
    assert r.json()["client_id"]
    assert r.json()["client_secret"]
    assert r.json()["token_endpoint_auth_method"] == "client_secret_post"


async def test_overwrites_supplied_client_id_and_secret(driver) -> None:
    # RFC 7591 §3.2.1: server replaces caller-supplied client_id/client_secret.
    r = await driver.request(
        "POST",
        "/oauth2/register",
        json_body={
            "name": "App",
            "redirect_uris": ["https://example.com/callback"],
            "token_endpoint_auth_method": "client_secret_post",
            "client_id": "bad-actor",
            "client_secret": "bad-actor",
        },
    )
    assert r.status == 200, r.json()
    assert r.json()["client_id"] != "bad-actor"
    assert r.json()["client_secret"] != "bad-actor"


async def test_reject_skip_consent_in_dcr(driver) -> None:
    # RFC 7591 §2: the server controls privileged metadata. A self-registering
    # client may not grant itself consent-skip (admin-only).
    r = await _register(driver, skip_consent=True)
    assert r.status == 400, r.json()


async def test_allow_registration_without_skip_consent(driver) -> None:
    r = await _register(driver)
    assert r.status == 200, r.json()
    assert r.json()["client_id"]


async def test_register_disabled_returns_404() -> None:
    auth = make_auth(enable_dynamic_registration=False)
    d = ASGIDriver(app=auth.router.mount())
    r = await d.request(
        "POST",
        "/oauth2/register",
        json_body={"name": "x", "redirect_uris": ["https://x/cb"]},
    )
    assert r.status == 404


@pytest.mark.skip(
    reason="Python DCR endpoint is not session-gated and has no "
    "organization/clientReference/metadata-spread machinery, nor an "
    "unauthenticated-registration mode (the upstream RFC 7591 §3.2.1 "
    "public-client override cases from issue #8588); those upstream cases "
    "require a data model the port does not implement."
)
async def test_session_and_organization_and_metadata_cases() -> None:
    ...
