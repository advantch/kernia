"""End-to-end: full RFC 8628 device-flow exchange."""

from __future__ import annotations

import pytest

from kernia.auth import init
from kernia.plugins import device_authorization, email_and_password
from kernia.types.init_options import KerniaOptions
from kernia_test_utils import ASGIDriver
from kernia_test_utils.adapter_fixtures import all_adapters_param


async def _make_adapter_with_device_code(adapter_factory) -> object:
    """Build an adapter that also knows about the deviceCode plugin table.

    The shared `all_adapters_param` fixture creates the adapter with core
    models only; we re-materialize the plugin schema for backends that need it.
    """
    adapter = await adapter_factory()
    create_schema = getattr(adapter, "create_schema", None)
    if create_schema is not None:
        from kernia.plugins.device_authorization.plugin import DEVICE_CODE_MODEL

        await create_schema(models=(DEVICE_CODE_MODEL,))
    return adapter


@pytest.mark.parametrize(*all_adapters_param())
async def test_full_device_flow(adapter_factory) -> None:
    adapter = await _make_adapter_with_device_code(adapter_factory)
    auth = init(
        KerniaOptions(
            database=adapter,
            secret="device-secret",
            plugins=[email_and_password(), device_authorization(interval=0)],
        )
    )
    driver = ASGIDriver(app=auth.router.mount())

    # 1. Client requests a device code.
    r = await driver.request(
        "POST",
        "/device/code",
        json_body={"client_id": "cli-app", "scope": "read"},
    )
    assert r.status == 200, r.json()
    payload = r.json()
    device_code = payload["device_code"]
    user_code = payload["user_code"]
    assert payload["verification_uri"].endswith("/device")
    assert user_code in payload["verification_uri_complete"]

    # 2. CLI starts polling — first poll returns authorization_pending.
    r = await driver.request(
        "POST",
        "/device/token",
        json_body={
            "device_code": device_code,
            "client_id": "cli-app",
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        },
    )
    assert r.status == 400, r.json()
    assert r.json()["code"] == "AUTHORIZATION_PENDING"

    # 3. Meanwhile a real user signs in via the browser and approves.
    user_driver = ASGIDriver(app=auth.router.mount())
    await user_driver.request(
        "POST",
        "/sign-up/email",
        json_body={"email": "human@example.com", "password": "approvepass"},
    )
    # GET /device claims the code for the active user.
    r = await user_driver.request("GET", "/device", query=f"user_code={user_code}")
    assert r.status == 200, r.json()
    assert r.json()["status"] == "pending"

    r = await user_driver.request(
        "POST",
        "/device/approve",
        json_body={"user_code": user_code},
    )
    assert r.status == 200, r.json()

    # 4. CLI polls again — now receives the access token (= session token).
    r = await driver.request(
        "POST",
        "/device/token",
        json_body={
            "device_code": device_code,
            "client_id": "cli-app",
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        },
    )
    assert r.status == 200, r.json()
    body = r.json()
    assert body["token_type"] == "Bearer"
    assert isinstance(body["access_token"], str) and body["access_token"]


@pytest.mark.parametrize(*all_adapters_param())
async def test_device_flow_denial(adapter_factory) -> None:
    adapter = await _make_adapter_with_device_code(adapter_factory)
    auth = init(
        KerniaOptions(
            database=adapter,
            secret="s",
            plugins=[email_and_password(), device_authorization(interval=0)],
        )
    )
    driver = ASGIDriver(app=auth.router.mount())

    r = await driver.request("POST", "/device/code", json_body={"client_id": "cli"})
    user_code = r.json()["user_code"]
    device_code = r.json()["device_code"]

    user_driver = ASGIDriver(app=auth.router.mount())
    await user_driver.request(
        "POST",
        "/sign-up/email",
        json_body={"email": "u@example.com", "password": "passpass1"},
    )
    await user_driver.request("GET", "/device", query=f"user_code={user_code}")
    r = await user_driver.request("POST", "/device/deny", json_body={"user_code": user_code})
    assert r.status == 200, r.json()

    r = await driver.request(
        "POST",
        "/device/token",
        json_body={
            "device_code": device_code,
            "client_id": "cli",
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        },
    )
    assert r.status == 400
    assert r.json()["code"] == "ACCESS_DENIED"
