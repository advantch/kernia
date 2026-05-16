"""SQLAlchemy 2.x async adapter.

Mirrors `reference/packages/better-auth/src/adapters/`-style adapter packages
(drizzle, prisma, kysely). Builds a single `metadata` from
`better_auth.db.schema.CORE_MODELS` plus any plugin-contributed schemas, and
performs CRUD via SQLAlchemy Core (no ORM session ceremony at the adapter layer).
"""

from better_auth_sqlalchemy.adapter import SQLAlchemyAdapter, sqlalchemy_adapter

__all__ = ["SQLAlchemyAdapter", "sqlalchemy_adapter"]
