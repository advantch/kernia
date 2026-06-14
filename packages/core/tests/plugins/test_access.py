"""Unit tests for the `access` primitives."""

from __future__ import annotations

import pytest
from kernia.plugins.access import (
    Role,
    create_access_control,
    default_roles,
    default_statements,
)


def _ac():
    return create_access_control(
        {
            "post": ("create", "read", "update", "delete"),
            "user": ("list", "ban"),
        }
    )


def test_new_role_validates_unknown_resource() -> None:
    ac = _ac()
    with pytest.raises(ValueError, match="unknown resource"):
        ac.new_role({"widget": ("read",)})


def test_new_role_validates_unknown_action() -> None:
    ac = _ac()
    with pytest.raises(ValueError, match="unknown action"):
        ac.new_role({"post": ("publish",)})


def test_authorize_and_connector_success() -> None:
    role = _ac().new_role({"post": ("read", "update")})
    r = role.authorize({"post": ("read", "update")})
    assert r.success is True
    assert r.error is None


def test_authorize_and_connector_missing_action() -> None:
    role = _ac().new_role({"post": ("read",)})
    r = role.authorize({"post": ("read", "update")})
    assert r.success is False
    assert "post" in (r.error or "")


def test_authorize_unknown_resource_fails() -> None:
    role = _ac().new_role({"post": ("read",)})
    r = role.authorize({"widget": ("read",)})
    assert r.success is False
    assert r.error and "widget" in r.error


def test_authorize_or_outer_connector_short_circuits_on_first_hit() -> None:
    role = _ac().new_role({"post": ("read",), "user": ()})
    r = role.authorize({"post": ("read",), "user": ("ban",)}, connector="OR")
    assert r.success is True


def test_authorize_or_inner_connector() -> None:
    role = _ac().new_role({"post": ("read",)})
    r = role.authorize({"post": {"actions": ("read", "delete"), "connector": "OR"}})
    assert r.success is True


def test_default_roles_admin_can_ban_user() -> None:
    roles = default_roles()
    assert isinstance(roles["admin"], Role)
    r = roles["admin"].authorize({"user": ("ban",)})
    assert r.success is True


def test_default_roles_regular_user_cannot_ban() -> None:
    roles = default_roles()
    r = roles["user"].authorize({"user": ("ban",)})
    assert r.success is False


def test_default_statements_shape() -> None:
    assert "user" in default_statements
    assert "ban" in default_statements["user"]


def test_invalid_request_value_type() -> None:
    role = _ac().new_role({"post": ("read",)})
    with pytest.raises(ValueError, match="Invalid"):
        role.authorize({"post": 42})  # type: ignore[arg-type]
