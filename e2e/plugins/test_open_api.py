"""End-to-end tests for the open_api plugin."""

from __future__ import annotations

import pytest
from better_auth.auth import init
from better_auth.plugins import email_and_password
from better_auth.plugins.open_api import open_api
from better_auth.types.init_options import BetterAuthOptions
from better_auth_memory_adapter import memory_adapter
from better_auth_test_utils import ASGIDriver


@pytest.fixture
def driver() -> ASGIDriver:
    auth = init(
        BetterAuthOptions(
            database=memory_adapter(),
            secret="x" * 32,
            plugins=[email_and_password(), open_api()],
        )
    )
    return ASGIDriver(app=auth.router.mount())


async def test_openapi_json_returns_valid_spec(driver: ASGIDriver) -> None:
    from openapi_spec_validator import validate

    r = await driver.request("GET", "/openapi.json")
    assert r.status == 200
    doc = r.json()
    assert doc["openapi"] == "3.1.0"
    validate(doc)


async def test_openapi_json_covers_core_and_plugin_routes(driver: ASGIDriver) -> None:
    r = await driver.request("GET", "/openapi.json")
    doc = r.json()
    # Core routes
    assert "/ok" in doc["paths"]
    assert "/list-sessions" in doc["paths"]
    # email-password
    assert "/sign-up/email" in doc["paths"]
    assert "/sign-in/email" in doc["paths"]
    # Self-registered
    assert "/openapi.json" in doc["paths"]
    assert "/scalar" in doc["paths"]


async def test_scalar_page_returns_html(driver: ASGIDriver) -> None:
    r = await driver.request("GET", "/scalar")
    assert r.status == 200
    content_type = dict(r.headers).get("content-type", "")
    assert "text/html" in content_type
    body = r.body.decode("utf-8")
    assert "<script" in body
    assert "openapi.json" in body
    assert "scalar/api-reference" in body
