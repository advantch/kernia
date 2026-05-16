"""Alembic codegen for plugin-contributed schemas.

Mirrors what `pnpm better-auth generate` does in the reference (emit a Drizzle/
Prisma schema). In Python we emit an Alembic migration script: the user runs
`alembic upgrade head` (or `better-auth migrate`) to apply.

Inputs:
  - `ModelDef[]` — every core model + every plugin's schema.tables
  - `dict[str, list[FieldDef]]` — plugin extensions to existing models

Output:
  A Python source string suitable to drop into `alembic/versions/<rev>.py`.
"""

from better_auth.db.migrations.codegen import (
    emit_migration,
    resolve_full_schema,
)

__all__ = ["emit_migration", "resolve_full_schema"]
