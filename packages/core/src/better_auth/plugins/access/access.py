"""Access-control primitives.

Mirrors `reference/packages/better-auth/src/plugins/access/access.ts`.

Two top-level helpers:

  * `create_access_control(statements)` — returns an `AccessControl` whose
    `new_role(role_statements)` constructs `Role` instances.
  * `default_roles()` — returns the built-in admin / user / guest map used by
    the `admin` plugin when no custom roles are supplied.

`Role.authorize(request, connector="AND")` returns an `AuthorizeResponse`. The
shape mirrors the TS implementation: each requested resource → actions is
checked against the role's allowed actions; under "AND" the role must permit
*every* requested resource, under "OR" at least one.

A request value may be either a plain `tuple[str, ...]` of actions or a dict of
the form `{"actions": (...), "connector": "AND"|"OR"}` to control inner-resource
combinator semantics.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal

# A statement set: maps resource name → tuple of allowed action names.
Statement = Mapping[str, tuple[str, ...]]

Connector = Literal["AND", "OR"]


@dataclass(frozen=True, slots=True)
class AuthorizeResponse:
    success: bool
    error: str | None = None


@dataclass(frozen=True)
class Role:
    """A role bound to a subset of an `AccessControl` statement set.

    `statements` is the role's permitted resource → actions map. `authorize`
    checks whether a *requested* statement is permitted.
    """

    statements: Statement

    def authorize(
        self,
        request: Mapping[str, Any],
        connector: Connector = "AND",
    ) -> AuthorizeResponse:
        success = False
        for resource, requested in request.items():
            allowed = self.statements.get(resource)
            if allowed is None:
                return AuthorizeResponse(
                    success=False,
                    error=f"You are not allowed to access resource: {resource}",
                )
            inner_connector: Connector = "AND"
            if isinstance(requested, dict):
                actions = tuple(requested.get("actions") or ())
                inner_connector = requested.get("connector", "AND")
            elif isinstance(requested, list | tuple):
                actions = tuple(requested)
            else:
                raise ValueError(f"Invalid access control request for {resource!r}")

            if inner_connector == "OR":
                success = any(a in allowed for a in actions) if actions else True
            else:
                success = all(a in allowed for a in actions) if actions else True

            if success and connector == "OR":
                return AuthorizeResponse(success=True)
            if not success and connector == "AND":
                return AuthorizeResponse(
                    success=False,
                    error=f'unauthorized to access resource "{resource}"',
                )

        if success:
            return AuthorizeResponse(success=True)
        return AuthorizeResponse(success=False, error="Not authorized")


def role(statements: Statement) -> Role:
    """Construct a `Role` from a statement set."""
    return Role(statements=dict(statements))


@dataclass(frozen=True)
class AccessControl:
    """Bundle of a parent statement set with a role-factory.

    Returned by `create_access_control`. Plugins use `.new_role({...})` to
    build admin / user / custom roles.
    """

    statements: Statement

    def new_role(self, role_statements: Statement) -> Role:
        # Validate that every requested resource exists in the parent set;
        # mirrors the TS `RoleInput` constraint at runtime.
        for resource, actions in role_statements.items():
            if resource not in self.statements:
                raise ValueError(
                    f"Role references unknown resource {resource!r}; "
                    f"declared resources: {sorted(self.statements)}"
                )
            allowed = set(self.statements[resource])
            for a in actions:
                if a not in allowed:
                    raise ValueError(
                        f"Role references unknown action {a!r} on resource {resource!r}; "
                        f"allowed: {sorted(allowed)}"
                    )
        return Role(statements=dict(role_statements))


def create_access_control(statements: Statement) -> AccessControl:
    """Top-level helper. Returns an `AccessControl` over `statements`."""
    return AccessControl(statements=dict(statements))


# ---------------------------------------------------------------------------
# Default statements + roles used by the `admin` plugin
# ---------------------------------------------------------------------------

default_statements: Statement = {
    "user": (
        "create",
        "list",
        "set-role",
        "ban",
        "impersonate",
        "impersonate-admins",
        "delete",
        "set-password",
        "get",
        "update",
    ),
    "session": ("list", "revoke", "delete"),
}

_default_ac = create_access_control(default_statements)


def default_roles() -> dict[str, Role]:
    """Return the canonical admin / user / guest roles.

    `admin` has full access; `user` and `guest` have no statements.
    """
    return {
        "admin": _default_ac.new_role(
            {
                "user": (
                    "create",
                    "list",
                    "set-role",
                    "ban",
                    "impersonate",
                    "delete",
                    "set-password",
                    "get",
                    "update",
                ),
                "session": ("list", "revoke", "delete"),
            }
        ),
        "user": _default_ac.new_role({}),
        "guest": _default_ac.new_role({}),
    }
