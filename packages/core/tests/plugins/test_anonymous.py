"""Unit tests for the anonymous plugin: schema + error codes + hooks shape."""

from __future__ import annotations

from better_auth.plugins.anonymous import ANONYMOUS_ERROR_CODES, anonymous


def test_anonymous_plugin_id_and_endpoint() -> None:
    p = anonymous()
    assert p.id == "anonymous"
    paths = {ep.path for ep in (p.endpoints or ())}
    assert "/sign-in/anonymous" in paths


def test_anonymous_extends_user_schema_with_is_anonymous() -> None:
    p = anonymous()
    assert p.schema is not None
    user_extras = p.schema.extend.get("user", ())
    field_map = {f.name: f for f in user_extras}
    assert "isAnonymous" in field_map
    assert field_map["isAnonymous"].default is False


def test_anonymous_registers_before_and_after_hooks() -> None:
    p = anonymous()
    assert p.hooks is not None
    assert len(p.hooks.before) == 1
    assert len(p.hooks.after) == 1


def test_anonymous_error_codes_documented() -> None:
    assert "ANONYMOUS_USERS_CANNOT_SIGN_IN_AGAIN_ANONYMOUSLY" in ANONYMOUS_ERROR_CODES
