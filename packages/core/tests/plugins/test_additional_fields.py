"""Tests for the additional_fields plugin."""

from __future__ import annotations

import pytest

from kernia.auth import init
from kernia.plugins.additional_fields import additional_fields
from kernia.plugins.email_password import email_and_password
from kernia.types.init_options import KerniaOptions
from kernia_memory_adapter import memory_adapter
from kernia_test_utils import ASGIDriver


def test_schema_extension_present() -> None:
    plugin = additional_fields({"user": {"company": {"type": "string", "required": True}}})
    assert plugin.schema is not None
    extended = plugin.schema.extend["user"]
    assert any(f.name == "company" and f.required for f in extended)


async def test_signup_persists_additional_fields() -> None:
    auth = init(
        KerniaOptions(
            database=memory_adapter(),
            secret="test-secret-key",
            plugins=[
                email_and_password(),
                additional_fields(
                    {
                        "user": {
                            "company": {"type": "string", "required": True},
                            "department": {"type": "string"},
                        }
                    }
                ),
            ],
        )
    )
    driver = ASGIDriver(app=auth.router.mount())
    r = await driver.request(
        "POST",
        "/sign-up/email",
        json_body={
            "email": "claire@example.com",
            "password": "secretpass",
            "company": "Acme",
            "department": "eng",
        },
    )
    assert r.status == 200, r.json()
    user = r.json()["user"]
    assert user["company"] == "Acme"
    assert user["department"] == "eng"


async def test_signup_missing_required_field_rejected() -> None:
    auth = init(
        KerniaOptions(
            database=memory_adapter(),
            secret="test-secret-key",
            plugins=[
                email_and_password(),
                additional_fields({"user": {"company": {"type": "string", "required": True}}}),
            ],
        )
    )
    driver = ASGIDriver(app=auth.router.mount())
    r = await driver.request(
        "POST",
        "/sign-up/email",
        json_body={"email": "x@example.com", "password": "secretpass"},
    )
    assert r.status == 400
    assert "company" in r.json()["message"]


def test_unknown_type_rejected() -> None:
    with pytest.raises(ValueError, match="Unsupported"):
        additional_fields({"user": {"bad": {"type": "color"}}})
