"""Canonical schema definitions.

Mirrors `reference/packages/better-auth/src/db/schema/`. The four core tables —
`user`, `session`, `account`, `verification` — are defined here as `ModelDef` values.
Plugins extend these via `PluginSchema.extend` or add new tables via `PluginSchema.tables`.
"""

from kernia.db.schema.core_tables import (
    ACCOUNT_MODEL,
    CORE_MODELS,
    SESSION_MODEL,
    USER_MODEL,
    VERIFICATION_MODEL,
)

__all__ = [
    "ACCOUNT_MODEL",
    "CORE_MODELS",
    "SESSION_MODEL",
    "USER_MODEL",
    "VERIFICATION_MODEL",
]
