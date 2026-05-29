"""Role-based access control DSL for the organization plugin.

Mirrors `reference/packages/better-auth/src/plugins/access/access.ts` and
`reference/.../plugins/organization/access/statement.ts`.

Concepts:

  * **Statement** — a `dict[str, tuple[str, ...]]` mapping a resource (e.g.
    ``"member"``) to the actions allowed on it (e.g. ``("create", "delete")``).
  * **Role** — a named bundle of permissions over a base statement.
  * **AccessControl** — a registry of resources + their full action set. Roles are
    created against it via :meth:`AccessControl.new_role`.
  * :func:`has_permission` — given a role name, a required statement, and the
    defined-role table, returns ``True`` iff every requested ``(resource, action)``
    pair is present in the role.

Built-in roles (``owner``, ``admin``, ``member``) match the JS reference.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

Statement = dict[str, tuple[str, ...]]


@dataclass(frozen=True, slots=True)
class Role:
    """A named, immutable permission bundle.

    Use :func:`define_role` or :meth:`AccessControl.new_role` to construct.
    """

    name: str
    statement: Statement

    def authorize(
        self, request: Mapping[str, Iterable[str]], *, connector: str = "AND"
    ) -> bool:
        """Return True if the role grants the requested permissions.

        ``request`` maps resource -> required actions. ``connector`` of ``"AND"``
        (default) requires every resource to authorize; ``"OR"`` requires at least
        one.
        """
        success = False
        for resource, actions in request.items():
            allowed = self.statement.get(resource)
            if allowed is None:
                if connector == "AND":
                    return False
                continue
            ok = all(action in allowed for action in actions)
            if ok and connector == "OR":
                return True
            if not ok and connector == "AND":
                return False
            success = success or ok
        return success


def define_role(name: str, statement: Statement) -> Role:
    """Construct a :class:`Role` from a name and a statement dict."""
    # Normalize all action collections to tuples for hashability/immutability.
    norm: Statement = {k: tuple(v) for k, v in statement.items()}
    return Role(name=name, statement=norm)


# camelCase alias kept to ease porting from the reference implementation.
defineRole = define_role  # -- TS-style alias is intentional


@dataclass(frozen=True, slots=True)
class AccessControl:
    """A registry of resources + valid actions.

    Use :meth:`new_role` to derive roles whose statements must be a subset of the
    registry's resources/actions. (We don't strictly enforce subset at construction
    — invalid resources surface at :func:`has_permission` time as a ``False``.)
    """

    statements: Mapping[str, tuple[str, ...]] = field(default_factory=dict)

    def new_role(self, name: str, statement: Statement) -> Role:
        return define_role(name, statement)

    # camelCase alias for parity.
    newRole = new_role


def create_access_control(
    statements: Mapping[str, Iterable[str]],
) -> AccessControl:
    """Create an :class:`AccessControl` registry."""
    norm = {k: tuple(v) for k, v in statements.items()}
    return AccessControl(statements=norm)


# camelCase alias.
createAccessControl = create_access_control


# ---------------------------------------------------------------------------
# Built-in role definitions for the organization plugin
# ---------------------------------------------------------------------------

DEFAULT_STATEMENTS: Mapping[str, tuple[str, ...]] = {
    "organization": ("update", "delete"),
    "member": ("create", "update", "delete"),
    "invitation": ("create", "cancel"),
    "team": ("create", "update", "delete"),
    "ac": ("create", "read", "update", "delete"),
}


default_ac = create_access_control(DEFAULT_STATEMENTS)


owner_role = default_ac.new_role(
    "owner",
    {
        "organization": ("update", "delete"),
        "member": ("create", "update", "delete"),
        "invitation": ("create", "cancel"),
        "team": ("create", "update", "delete"),
        "ac": ("create", "read", "update", "delete"),
    },
)


admin_role = default_ac.new_role(
    "admin",
    {
        "organization": ("update",),  # NOTE: admin cannot delete the org
        "member": ("create", "update", "delete"),
        "invitation": ("create", "cancel"),
        "team": ("create", "update", "delete"),
        "ac": ("create", "read", "update", "delete"),
    },
)


member_role = default_ac.new_role(
    "member",
    {
        "organization": (),
        "member": (),
        "invitation": (),
        "team": (),
        "ac": ("read",),  # members can see roles for their org
    },
)


DEFAULT_ROLES: Mapping[str, Role] = {
    "owner": owner_role,
    "admin": admin_role,
    "member": member_role,
}


# ---------------------------------------------------------------------------
# Permission check
# ---------------------------------------------------------------------------


def has_permission(
    active_role: str,
    required: Mapping[str, Iterable[str]],
    defined_roles: Mapping[str, Role] | None = None,
    *,
    connector: str = "AND",
) -> bool:
    """Return ``True`` if ``active_role`` grants every requested permission.

    ``required`` is a statement: ``{"<resource>": ["<action>", ...]}``. The role
    table defaults to :data:`DEFAULT_ROLES`; pass a different mapping when dynamic
    access control is enabled to merge custom roles into the table.
    """
    table = defined_roles if defined_roles is not None else DEFAULT_ROLES
    role = table.get(active_role)
    if role is None:
        return False
    return role.authorize(required, connector=connector)


def merge_dynamic_roles(
    rows: Iterable[Mapping[str, Any]],
    *,
    base: Mapping[str, Role] = DEFAULT_ROLES,
) -> dict[str, Role]:
    """Build a role table that overlays ``rows`` from the ``organizationRole``
    table on top of ``base`` (the built-in roles).

    Each row must contain ``role`` (name) and ``permissions`` (a statement dict).
    Rows with the same name override an existing entry — this is the dynamic-AC
    upgrade path.
    """
    out: dict[str, Role] = dict(base)
    for row in rows:
        name = row.get("role")
        perms = row.get("permissions")
        if not isinstance(name, str) or not isinstance(perms, Mapping):
            continue
        statement: Statement = {
            str(k): tuple(v) for k, v in perms.items() if isinstance(v, list | tuple)
        }
        out[name] = define_role(name, statement)
    return out


__all__ = [
    "AccessControl",
    "DEFAULT_ROLES",
    "DEFAULT_STATEMENTS",
    "Role",
    "Statement",
    "admin_role",
    "create_access_control",
    "createAccessControl",
    "default_ac",
    "defineRole",
    "define_role",
    "has_permission",
    "member_role",
    "merge_dynamic_roles",
    "owner_role",
]
