"""SCIM PatchOp -> user/account update builder.

Mirrors ``reference/packages/scim/src/patch-operations.ts``. Translates a list of
RFC 7644 PatchOps into a ``{"user": {...}, "account": {...}}`` pair of column
updates. Only ``add`` and ``replace`` ops contribute; ``remove`` is ignored.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from better_auth_scim.mappings import get_user_full_name

# A mapping describes how a normalized path maps onto a target column.
# Each entry: {"resource": "user"|"account", "target": str, "map": fn}
Mapping_T = dict[str, Any]


def _identity(user: Mapping[str, Any], op: dict[str, Any], resources: dict) -> Any:
    return op["value"]


def _lower_case(user: Mapping[str, Any], op: dict[str, Any], resources: dict) -> Any:
    return op["value"].lower()


def _given_name(user: Mapping[str, Any], op: dict[str, Any], resources: dict) -> Any:
    current_name = resources["user"].get("name") or user.get("name") or ""
    family_name = " ".join(current_name.split(" ")[1:]).strip()
    given_name = op["value"]
    return get_user_full_name(
        user.get("email", ""),
        {"givenName": given_name, "familyName": family_name},
    )


def _family_name(user: Mapping[str, Any], op: dict[str, Any], resources: dict) -> Any:
    current_name = resources["user"].get("name") or user.get("name") or ""
    parts = current_name.split(" ")
    given_name = (" ".join(parts[:-1]) or current_name).strip()
    family_name = op["value"]
    return get_user_full_name(
        user.get("email", ""),
        {"givenName": given_name, "familyName": family_name},
    )


_USER_PATCH_MAPPINGS: dict[str, Mapping_T] = {
    "/name/formatted": {"resource": "user", "target": "name", "map": _identity},
    "/name/givenName": {"resource": "user", "target": "name", "map": _given_name},
    "/name/familyName": {"resource": "user", "target": "name", "map": _family_name},
    "/externalId": {"resource": "account", "target": "accountId", "map": _identity},
    "/userName": {"resource": "user", "target": "email", "map": _lower_case},
}


def _normalize_path(path: str) -> str:
    without_leading = path[1:] if path.startswith("/") else path
    return "/" + without_leading.replace(".", "/")


def _is_nested_object(value: Any) -> bool:
    return isinstance(value, Mapping)


def _apply_mapping(
    user: Mapping[str, Any],
    resources: dict[str, dict[str, Any]],
    path: str,
    value: Any,
    op: str,
) -> None:
    normalized_path = _normalize_path(path)
    mapping = _USER_PATCH_MAPPINGS.get(normalized_path)
    if not mapping:
        return

    map_fn: Callable[..., Any] = mapping["map"]
    new_value = map_fn(
        user,
        {"op": op, "value": value, "path": normalized_path},
        resources,
    )

    if op == "add" and mapping["resource"] == "user":
        current_value = user.get(mapping["target"])
        if current_value == new_value:
            return

    resources[mapping["resource"]][mapping["target"]] = new_value


def _apply_patch_value(
    user: Mapping[str, Any],
    resources: dict[str, dict[str, Any]],
    value: Any,
    op: str,
    path: str | None = None,
) -> None:
    if _is_nested_object(value):
        for key, nested_value in value.items():
            nested_path = f"{path}.{key}" if path else key
            _apply_patch_value(user, resources, nested_value, op, nested_path)
    elif path:
        _apply_mapping(user, resources, path, value, op)


def build_user_patch(
    user: Mapping[str, Any], operations: list[Mapping[str, Any]]
) -> dict[str, dict[str, Any]]:
    """Return ``{"user": {...}, "account": {...}}`` updates for ``operations``."""
    resources: dict[str, dict[str, Any]] = {"user": {}, "account": {}}

    for operation in operations:
        op = operation.get("op")
        if op not in ("add", "replace"):
            continue
        _apply_patch_value(
            user,
            resources,
            operation.get("value"),
            op,
            operation.get("path"),
        )

    return resources
