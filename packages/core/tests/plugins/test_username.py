"""Unit tests for the username plugin: schema + error codes + plugin shape."""

from __future__ import annotations

from kernia.plugins.username import USERNAME_ERROR_CODES, username


def test_username_plugin_id_and_endpoints() -> None:
    p = username()
    assert p.id == "username"
    paths = {ep.path for ep in (p.endpoints or ())}
    assert {"/sign-up/username", "/sign-in/username"} <= paths


def test_username_plugin_extends_user_schema_with_unique_username() -> None:
    p = username()
    assert p.schema is not None
    user_extras = p.schema.extend.get("user", ())
    field_map = {f.name: f for f in user_extras}
    assert "username" in field_map
    assert "displayUsername" in field_map
    assert field_map["username"].unique is True
    assert field_map["username"].required is False


def test_username_error_codes_documented() -> None:
    assert "USERNAME_IS_ALREADY_TAKEN" in USERNAME_ERROR_CODES
    assert "INVALID_USERNAME_OR_PASSWORD" in USERNAME_ERROR_CODES
    assert "USERNAME_TOO_SHORT" in USERNAME_ERROR_CODES
    assert "USERNAME_TOO_LONG" in USERNAME_ERROR_CODES
