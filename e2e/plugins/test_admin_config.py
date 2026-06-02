"""End-to-end tests for database-backed admin configuration."""

from __future__ import annotations

from kernia.auth import init
from kernia.plugins.admin_config import AdminConfigOptions, admin_config
from kernia.plugins.email_password import email_and_password
from kernia.types.adapter import Where
from kernia.types.init_options import KerniaOptions
from kernia_memory_adapter import memory_adapter
from kernia_test_utils import ASGIDriver


async def _driver() -> tuple[ASGIDriver, object]:
    db = memory_adapter()
    auth = init(
        KerniaOptions(
            database=db,
            secret="test-secret",
            plugins=[
                admin_config(AdminConfigOptions(admin_roles=("admin",))),
                email_and_password(),
            ],
        )
    )
    driver = ASGIDriver(app=auth.router.mount())
    res = await driver.request(
        "POST",
        "/sign-up/email",
        json_body={"email": "root@example.com", "password": "rootpass!", "name": "Root"},
    )
    assert res.status == 200, res.json()
    await db.update(
        model="user",
        where=(Where(field="id", value=res.json()["user"]["id"]),),
        update={"role": "admin"},
    )
    return driver, auth


async def test_admin_config_auth_method_gate() -> None:
    driver, _auth = await _driver()

    res = await driver.request("GET", "/admin/config/public-auth")
    assert res.status == 200
    assert res.json()["methods"]["email-password"]["enabled"] is True

    res = await driver.request(
        "POST",
        "/admin/config/auth-methods",
        json_body={"value": {"email-password": {"enabled": False}}},
    )
    assert res.status == 200
    assert res.json()["methods"]["email-password"]["enabled"] is False

    await driver.request("POST", "/sign-out")
    driver.cookies.clear()
    res = await driver.request(
        "POST",
        "/sign-in/email",
        json_body={"email": "root@example.com", "password": "rootpass!"},
    )
    assert res.status == 403
    assert res.json()["code"] == "AUTH_METHOD_DISABLED"


async def test_admin_config_redacts_email_and_stripe_secrets() -> None:
    driver, _auth = await _driver()

    res = await driver.request(
        "POST",
        "/admin/config/email-clients",
        json_body={
            "value": {
                "clients": [
                    {
                        "id": "postmark-main",
                        "kind": "postmark",
                        "from": "support@example.com",
                        "apiKey": "pm-secret",
                    }
                ]
            },
            "secretFields": ["apiKey"],
        },
    )
    assert res.status == 200
    assert res.json()["clients"][0]["apiKey"] == "********"

    res = await driver.request(
        "POST",
        "/admin/config/stripe",
        json_body={
            "value": {"mode": "test", "apiKey": "sk_test_123", "webhookSecret": "whsec"},
        },
    )
    assert res.status == 200
    assert res.json()["stripe"]["apiKey"] == "********"
    assert res.json()["stripe"]["webhookSecret"] == "********"
