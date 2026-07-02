"""SCIM PatchOp interpreter.

A SCIM PATCH body looks like:

    {
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [
            {"op": "Add", "path": "displayName", "value": "Foo"},
            {"op": "Replace", "path": "active", "value": False},
            {"op": "Remove", "path": "name.familyName"},
        ],
    }

We accept the three canonical ops (`add`/`replace`/`remove`, case-insensitive)
and apply them to a SCIM user JSON document. Returns the mutated document.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, MutableMapping
from typing import Any


def _set_path(doc: MutableMapping[str, Any], path: str, value: Any) -> None:
    parts = path.split(".")
    cur: Any = doc
    for p in parts[:-1]:
        if (
            not isinstance(cur, MutableMapping)
            or p not in cur
            or not isinstance(cur[p], MutableMapping)
        ):
            cur[p] = {}  # type: ignore[index]
        cur = cur[p]
    cur[parts[-1]] = value  # type: ignore[index]


def _del_path(doc: MutableMapping[str, Any], path: str) -> None:
    parts = path.split(".")
    cur: Any = doc
    for p in parts[:-1]:
        if not isinstance(cur, MutableMapping) or p not in cur:
            return
        cur = cur[p]
    if isinstance(cur, MutableMapping):
        cur.pop(parts[-1], None)


def apply_patch_ops(
    document: MutableMapping[str, Any],
    operations: Iterable[Mapping[str, Any]],
) -> MutableMapping[str, Any]:
    """Apply a list of SCIM PatchOps to `document` in place. Returns it."""
    for raw in operations:
        op = str(raw.get("op", "")).lower()
        path = raw.get("path")
        value = raw.get("value")
        if op == "add":
            if path is None:
                # Bulk-merge: value must be a mapping.
                if isinstance(value, Mapping):
                    for k, v in value.items():
                        _set_path(document, k, v)
            else:
                _set_path(document, str(path), value)
        elif op == "replace":
            if path is None:
                if isinstance(value, Mapping):
                    for k, v in value.items():
                        _set_path(document, k, v)
            else:
                _set_path(document, str(path), value)
        elif op == "remove":
            if path is not None:
                _del_path(document, str(path))
        else:
            raise ValueError(f"Unsupported SCIM op {op!r}")
    return document
