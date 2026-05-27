"""Unit tests for the organization plugin's role/permission DSL.

Mirrors the matrices in
``reference/packages/better-auth/src/plugins/organization/access/`` and
``reference/.../plugins/access/access.test.ts``. Covers:

* The built-in owner / admin / member roles
* Custom role construction via :func:`create_access_control`
* Dynamic AC via :func:`merge_dynamic_roles`
* OR/AND connectors in :meth:`Role.authorize`
"""

from __future__ import annotations

import pytest

from kernia.plugins.organization.access_control import (
    DEFAULT_ROLES,
    DEFAULT_STATEMENTS,
    Role,
    admin_role,
    create_access_control,
    define_role,
    has_permission,
    member_role,
    merge_dynamic_roles,
    owner_role,
)


# ---------------------------------------------------------------------------
# Built-in roles
# ---------------------------------------------------------------------------


def test_owner_can_delete_organization() -> None:
    assert has_permission("owner", {"organization": ["delete"]})


def test_owner_can_update_organization() -> None:
    assert has_permission("owner", {"organization": ["update"]})


def test_owner_can_create_member() -> None:
    assert has_permission("owner", {"member": ["create"]})


def test_owner_can_invite_and_cancel() -> None:
    assert has_permission(
        "owner", {"invitation": ["create", "cancel"]}
    )


def test_owner_can_manage_ac_fully() -> None:
    assert has_permission(
        "owner", {"ac": ["create", "read", "update", "delete"]}
    )


def test_admin_can_update_org() -> None:
    assert has_permission("admin", {"organization": ["update"]})


def test_admin_cannot_delete_organization() -> None:
    assert not has_permission("admin", {"organization": ["delete"]})


def test_admin_can_create_member() -> None:
    assert has_permission("admin", {"member": ["create"]})


def test_admin_can_invite_and_cancel() -> None:
    assert has_permission(
        "admin", {"invitation": ["create", "cancel"]}
    )


def test_member_cannot_update_organization() -> None:
    assert not has_permission("member", {"organization": ["update"]})


def test_member_cannot_delete_organization() -> None:
    assert not has_permission("member", {"organization": ["delete"]})


def test_member_cannot_create_member() -> None:
    assert not has_permission("member", {"member": ["create"]})


def test_member_cannot_invite() -> None:
    assert not has_permission("member", {"invitation": ["create"]})


def test_member_can_read_ac() -> None:
    """Members can list their org's roles for client display."""
    assert has_permission("member", {"ac": ["read"]})


def test_member_cannot_write_ac() -> None:
    assert not has_permission("member", {"ac": ["create"]})


# ---------------------------------------------------------------------------
# Unknown role / resource / action
# ---------------------------------------------------------------------------


def test_unknown_role_is_denied() -> None:
    assert not has_permission("ghost", {"organization": ["update"]})


def test_unknown_resource_is_denied() -> None:
    assert not has_permission("owner", {"galaxy": ["spin"]})


def test_unknown_action_is_denied() -> None:
    assert not has_permission("owner", {"organization": ["levitate"]})


def test_partial_actions_are_denied_under_and() -> None:
    """AND (default) requires every requested action to be present."""
    # member can read ac but cannot delete it; AND should fail.
    assert not has_permission("member", {"ac": ["read", "delete"]})


def test_or_connector_across_resources_succeeds_if_one_resource_authorizes() -> None:
    """The connector applies across top-level resources, not within actions.

    Within a single resource, ALL requested actions must be allowed (matches
    the TS reference's `every` over `requestedActions`).
    """
    # member has ac.read but lacks organization.delete entirely; OR succeeds.
    assert has_permission(
        "member",
        {"organization": ["delete"], "ac": ["read"]},
        connector="OR",
    )


def test_or_across_resources() -> None:
    # member has no organization perms but does have ac.read; OR should pass.
    assert has_permission(
        "member",
        {"organization": ["update"], "ac": ["read"]},
        connector="OR",
    )


def test_and_across_resources_fails_when_one_missing() -> None:
    assert not has_permission(
        "member",
        {"organization": ["update"], "ac": ["read"]},
        connector="AND",
    )


# ---------------------------------------------------------------------------
# Custom AccessControl + Role
# ---------------------------------------------------------------------------


def test_create_access_control_round_trip() -> None:
    ac = create_access_control({"posts": ("read", "write", "delete")})
    assert ac.statements["posts"] == ("read", "write", "delete")


def test_new_role_creates_a_role_object() -> None:
    ac = create_access_control({"posts": ("read", "write")})
    role = ac.new_role("editor", {"posts": ("read", "write")})
    assert isinstance(role, Role)
    assert role.name == "editor"
    assert role.statement == {"posts": ("read", "write")}


def test_define_role_normalizes_lists_to_tuples() -> None:
    role = define_role("worker", {"task": ["complete"]})
    assert role.statement == {"task": ("complete",)}


def test_role_authorize_grants_when_actions_subset() -> None:
    role = define_role("editor", {"posts": ("read", "write")})
    assert role.authorize({"posts": ["read"]})
    assert role.authorize({"posts": ["read", "write"]})


def test_role_authorize_rejects_when_action_missing() -> None:
    role = define_role("editor", {"posts": ("read", "write")})
    assert not role.authorize({"posts": ["delete"]})


def test_role_authorize_rejects_unknown_resource_under_and() -> None:
    role = define_role("editor", {"posts": ("read",)})
    assert not role.authorize({"comments": ["read"]})


def test_role_authorize_or_skips_unknown_resource() -> None:
    role = define_role("editor", {"posts": ("read",)})
    assert role.authorize(
        {"comments": ["read"], "posts": ["read"]}, connector="OR"
    )


# ---------------------------------------------------------------------------
# Dynamic AC
# ---------------------------------------------------------------------------


def test_merge_dynamic_roles_overlays_on_defaults() -> None:
    table = merge_dynamic_roles(
        [{"role": "writer", "permissions": {"posts": ["read", "write"]}}]
    )
    assert "writer" in table
    assert "owner" in table  # defaults preserved
    assert table["writer"].statement == {"posts": ("read", "write")}


def test_dynamic_role_grants_custom_permissions() -> None:
    table = merge_dynamic_roles(
        [{"role": "writer", "permissions": {"posts": ["read", "write"]}}]
    )
    assert has_permission("writer", {"posts": ["read"]}, table)
    assert has_permission("writer", {"posts": ["write"]}, table)


def test_dynamic_role_denies_undeclared_actions() -> None:
    """Custom role with {"posts": ("read", "write")} allows write but not delete."""
    table = merge_dynamic_roles(
        [{"role": "writer", "permissions": {"posts": ["read", "write"]}}]
    )
    assert not has_permission("writer", {"posts": ["delete"]}, table)


def test_dynamic_role_overrides_builtin_when_same_name() -> None:
    table = merge_dynamic_roles(
        [{"role": "admin", "permissions": {"organization": ["delete"]}}]
    )
    # Override gave admin delete-org, which the default admin did NOT have.
    assert has_permission("admin", {"organization": ["delete"]}, table)


def test_merge_dynamic_roles_skips_malformed_rows() -> None:
    table = merge_dynamic_roles(
        [
            {"role": None, "permissions": {"posts": ["read"]}},  # no name
            {"role": "x", "permissions": "not-a-dict"},  # bad perms
            {"role": "y", "permissions": {"posts": ["read"]}},  # ok
        ]
    )
    assert "y" in table
    assert "x" not in table


# ---------------------------------------------------------------------------
# Role objects (instance API)
# ---------------------------------------------------------------------------


def test_default_role_instances_match_role_table() -> None:
    assert DEFAULT_ROLES["owner"] is owner_role
    assert DEFAULT_ROLES["admin"] is admin_role
    assert DEFAULT_ROLES["member"] is member_role


def test_default_statements_contain_expected_resources() -> None:
    for resource in ("organization", "member", "invitation", "team", "ac"):
        assert resource in DEFAULT_STATEMENTS


@pytest.mark.parametrize(
    "role_name,resource,action,expected",
    [
        ("owner", "organization", "update", True),
        ("owner", "organization", "delete", True),
        ("owner", "member", "create", True),
        ("admin", "organization", "update", True),
        ("admin", "organization", "delete", False),
        ("admin", "member", "delete", True),
        ("member", "organization", "update", False),
        ("member", "member", "create", False),
        ("member", "ac", "read", True),
        ("member", "ac", "delete", False),
    ],
)
def test_built_in_role_matrix(
    role_name: str, resource: str, action: str, expected: bool
) -> None:
    assert (
        has_permission(role_name, {resource: [action]}) is expected
    ), f"{role_name} {resource}.{action}"
