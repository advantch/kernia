"""Adapter factory + transforms.

Mirrors `reference/packages/better-auth/src/db/adapter/`. The factory wraps a raw
`CustomAdapter` with model/field-name remapping (camelCase ↔ snake_case) and applies
plugin schema extensions.
"""

from better_auth.db.adapter.factory import create_adapter
from better_auth.db.adapter.transforms import (
    transform_input,
    transform_output,
    transform_where,
)

__all__ = [
    "create_adapter",
    "transform_input",
    "transform_output",
    "transform_where",
]
