"""SQLAlchemy async adapter — implements `CustomAdapter`.

Wraps an `AsyncEngine`. Builds tables from `ModelDef` so the same schema definition
that the memory adapter uses also drives Postgres/MySQL/SQLite.
"""

from __future__ import annotations

import contextlib
import secrets
import time
import uuid as uuid_mod
from collections.abc import AsyncIterator, Sequence
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any

from kernia.db.schema import CORE_MODELS
from kernia.types.adapter import (
    CustomAdapter,
    FieldDef,
    JoinConfig,
    ModelDef,
    Record,
    SortBy,
    Where,
)
from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    ForeignKey,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    Uuid,
    and_,
    func,
    or_,
)
from sqlalchemy import delete as sa_delete
from sqlalchemy import insert as sa_insert
from sqlalchemy import select as sa_select
from sqlalchemy import update as sa_update
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, create_async_engine


def _sa_type(f: FieldDef) -> Any:
    match f.type:
        case "string":
            return String(255)
        case "uuid":
            return Uuid(as_uuid=True)
        case "text":
            return Text()
        case "number":
            return Integer()
        case "boolean":
            return Boolean()
        case "date":
            return Integer()  # unix seconds — keeps wire shape identical to memory
        case "json" | "string[]" | "number[]":
            return JSON()
        case _:  # pragma: no cover
            raise ValueError(f"unknown field type: {f.type}")


def build_metadata(models: Sequence[ModelDef]) -> MetaData:
    md = MetaData()
    for model in models:
        cols: list[Column] = []
        for f in model.fields:
            kwargs: dict[str, Any] = {
                "primary_key": (f.name == "id"),
                "unique": f.unique and f.name != "id",
                "nullable": not f.required,
            }
            if f.default is not None or f.default is False:
                # SQLAlchemy treats falsey defaults as missing unless we pass them
                # explicitly. Boolean `default=False` is a legitimate default.
                if f.default is not None or f.type == "boolean":
                    kwargs["default"] = f.default
            # UUID primary keys auto-generate via uuid4 server-side.
            if f.name == "id" and f.type == "uuid":
                kwargs["default"] = uuid_mod.uuid4
            args: list[Any] = [_sa_type(f)]
            if f.references is not None:
                ref_model, ref_field = f.references
                args.append(ForeignKey(f"{ref_model}.{ref_field}"))
            cols.append(Column(f.name, *args, **kwargs))
        Table(model.name, md, *cols)
    return md


def _column(table: Table, name: str) -> Column:
    return getattr(table.c, name)


def _where_to_sql(table: Table, where: Sequence[Where]) -> Any:
    if not where:
        return None
    expr: Any = None
    for clause in where:
        col = _column(table, clause.field)
        op = clause.operator
        val = clause.value
        match op:
            case "eq":
                cond = col == val
            case "ne":
                cond = col != val
            case "lt":
                cond = col < val
            case "lte":
                cond = col <= val
            case "gt":
                cond = col > val
            case "gte":
                cond = col >= val
            case "in":
                cond = col.in_(val)
            case "not_in":
                cond = ~col.in_(val)
            case "contains":
                cond = col.contains(val)
            case "starts_with":
                cond = col.startswith(val)
            case "ends_with":
                cond = col.endswith(val)
            case "ilike_eq":
                cond = func.lower(col) == func.lower(val)
            case _:  # pragma: no cover
                raise ValueError(f"unsupported operator: {op}")
        if expr is None:
            expr = cond
        elif clause.connector == "AND":
            expr = and_(expr, cond)
        else:
            expr = or_(expr, cond)
    return expr


def _row_to_dict(row: Any, select: Sequence[str] | None) -> Record:
    data = dict(row._mapping)
    if select:
        data = {k: data[k] for k in select if k in data}
    return data


@dataclass
class SQLAlchemyAdapter:
    engine: AsyncEngine
    metadata: MetaData = field(default_factory=MetaData)
    models: tuple[ModelDef, ...] = ()
    # Per-task active transaction connection. When set inside `transaction()`
    # every CRUD method uses this connection so the work happens in one txn.
    _txn_conn: ContextVar[AsyncConnection | None] = field(
        default_factory=lambda: ContextVar("kernia_sa_txn", default=None)
    )

    def _table(self, model: str) -> Table:
        try:
            return self.metadata.tables[model]
        except KeyError:
            raise ValueError(f"unknown model: {model}") from None

    @contextlib.asynccontextmanager
    async def _connect(self, *, write: bool) -> AsyncIterator[AsyncConnection]:
        """Yield a connection.

        - If a transaction is in progress, reuse its connection (no commit).
        - Otherwise open a fresh connection (committing on `write=True`).
        """
        active = self._txn_conn.get()
        if active is not None:
            yield active
            return
        if write:
            async with self.engine.begin() as conn:
                yield conn
        else:
            async with self.engine.connect() as conn:
                yield conn

    def _id_default(self, table: Table) -> Any:
        """Generate a fresh PK value matching the table's id-column type."""
        id_col = table.c.id
        if isinstance(id_col.type, Uuid):
            return uuid_mod.uuid4()
        return secrets.token_urlsafe(16)

    async def create(
        self,
        *,
        model: str,
        data: Record,
        select: Sequence[str] | None = None,
    ) -> Record:
        table = self._table(model)
        row = dict(data)
        row.setdefault("id", self._id_default(table))
        row.setdefault("createdAt", int(time.time()))
        row.setdefault("updatedAt", int(time.time()))
        async with self._connect(write=True) as conn:
            await conn.execute(sa_insert(table).values(**row))
            inserted = (
                await conn.execute(sa_select(table).where(_column(table, "id") == row["id"]))
            ).first()
        if inserted is None:
            return row
        return _row_to_dict(inserted, select)

    async def find_one(
        self,
        *,
        model: str,
        where: Sequence[Where],
        select: Sequence[str] | None = None,
        join: JoinConfig | None = None,
    ) -> Record | None:
        table = self._table(model)
        expr = _where_to_sql(table, where)
        if join is not None:
            stmt = self._select_with_join(table, select, join)
            if expr is not None:
                stmt = stmt.where(expr)
            async with self._connect(write=False) as conn:
                row = (await conn.execute(stmt.limit(1))).first()
            if row is None:
                return None
            return self._project_joined(row, table, select, join)

        stmt = sa_select(table).where(expr) if expr is not None else sa_select(table)
        async with self._connect(write=False) as conn:
            row = (await conn.execute(stmt.limit(1))).first()
        if row is None:
            return None
        return _row_to_dict(row, select)

    async def find_many(
        self,
        *,
        model: str,
        where: Sequence[Where] = (),
        limit: int | None = None,
        offset: int | None = None,
        sort_by: SortBy | None = None,
        select: Sequence[str] | None = None,
        join: JoinConfig | None = None,
    ) -> list[Record]:
        table = self._table(model)
        if join is not None:
            stmt = self._select_with_join(table, select, join)
        else:
            stmt = sa_select(table)
        expr = _where_to_sql(table, where)
        if expr is not None:
            stmt = stmt.where(expr)
        if sort_by is not None:
            col = _column(table, sort_by.field)
            stmt = stmt.order_by(col.desc() if sort_by.direction == "desc" else col.asc())
        if offset:
            stmt = stmt.offset(offset)
        if limit is not None:
            stmt = stmt.limit(limit)
        async with self._connect(write=False) as conn:
            rows = (await conn.execute(stmt)).all()
        if join is not None:
            return [self._project_joined(r, table, select, join) for r in rows]
        return [_row_to_dict(r, select) for r in rows]

    def _select_with_join(
        self,
        table: Table,
        select: Sequence[str] | None,
        join: JoinConfig,
    ) -> Any:
        """Build a SELECT with an explicit SQL join.

        The local field `join.on` joins the foreign model on `join.foreign_field`.
        The foreign columns are exposed with a unique label prefix so we can pull
        them back out into a nested dict in `_project_joined`.
        """
        foreign_table = self._table(join.model)
        local_col = _column(table, join.on)
        foreign_col = _column(foreign_table, join.foreign_field)
        cols: list[Any] = [c.label(f"__l__{c.name}") for c in table.c]
        cols.extend(c.label(f"__r__{c.name}") for c in foreign_table.c)
        return sa_select(*cols).select_from(
            table.outerjoin(foreign_table, local_col == foreign_col)
        )

    def _project_joined(
        self,
        row: Any,
        table: Table,
        select: Sequence[str] | None,
        join: JoinConfig,
    ) -> Record:
        m = dict(row._mapping)
        local = {c.name: m[f"__l__{c.name}"] for c in table.c}
        foreign_table = self._table(join.model)
        foreign_vals = {c.name: m[f"__r__{c.name}"] for c in foreign_table.c}
        foreign: Record | None = (
            foreign_vals if any(v is not None for v in foreign_vals.values()) else None
        )
        if select:
            local = {k: local[k] for k in select if k in local}
        local[join.as_] = foreign
        return local

    async def update(
        self,
        *,
        model: str,
        where: Sequence[Where],
        update: Record,
    ) -> Record | None:
        table = self._table(model)
        expr = _where_to_sql(table, where)
        if expr is None:
            return None
        patch = dict(update)
        patch["updatedAt"] = int(time.time())
        async with self._connect(write=True) as conn:
            await conn.execute(sa_update(table).where(expr).values(**patch))
            row = (await conn.execute(sa_select(table).where(expr).limit(1))).first()
        return _row_to_dict(row, None) if row else None

    async def update_many(
        self,
        *,
        model: str,
        where: Sequence[Where],
        update: Record,
    ) -> int:
        table = self._table(model)
        expr = _where_to_sql(table, where)
        patch = dict(update)
        patch["updatedAt"] = int(time.time())
        stmt = sa_update(table)
        if expr is not None:
            stmt = stmt.where(expr)
        async with self._connect(write=True) as conn:
            result = await conn.execute(stmt.values(**patch))
        return int(result.rowcount or 0)

    async def delete(
        self,
        *,
        model: str,
        where: Sequence[Where],
    ) -> None:
        table = self._table(model)
        expr = _where_to_sql(table, where)
        if expr is None:
            return
        async with self._connect(write=True) as conn:
            row = (await conn.execute(sa_select(table).where(expr).limit(1))).first()
            if row is None:
                return
            await conn.execute(sa_delete(table).where(_column(table, "id") == row.id))

    async def delete_many(
        self,
        *,
        model: str,
        where: Sequence[Where],
    ) -> int:
        table = self._table(model)
        expr = _where_to_sql(table, where)
        stmt = sa_delete(table)
        if expr is not None:
            stmt = stmt.where(expr)
        async with self._connect(write=True) as conn:
            result = await conn.execute(stmt)
        return int(result.rowcount or 0)

    async def count(
        self,
        *,
        model: str,
        where: Sequence[Where] = (),
    ) -> int:
        table = self._table(model)
        expr = _where_to_sql(table, where)
        stmt = sa_select(func.count()).select_from(table)
        if expr is not None:
            stmt = stmt.where(expr)
        async with self._connect(write=False) as conn:
            return int((await conn.execute(stmt)).scalar() or 0)

    async def consume_one(
        self,
        *,
        model: str,
        where: Sequence[Where],
    ) -> Record | None:
        table = self._table(model)
        expr = _where_to_sql(table, where)
        if expr is None:
            return None
        async with self._connect(write=True) as conn:
            row = (await conn.execute(sa_select(table).where(expr).limit(1))).first()
            if row is None:
                return None
            await conn.execute(sa_delete(table).where(_column(table, "id") == row.id))
            return _row_to_dict(row, None)

    async def create_schema(self, *, models: Sequence[ModelDef]) -> None:
        self.metadata = build_metadata(list(self.models) + list(models))
        async with self.engine.begin() as conn:
            await conn.run_sync(self.metadata.create_all)

    @contextlib.asynccontextmanager
    async def transaction(self) -> AsyncIterator[None]:
        """Run a batch of adapter calls under a single SQL transaction.

        On clean exit the transaction commits; on exception it rolls back. Nested
        calls reuse the outer connection (no savepoint nesting yet).
        """
        if self._txn_conn.get() is not None:
            yield
            return
        async with self.engine.begin() as conn:
            token = self._txn_conn.set(conn)
            try:
                yield
            finally:
                self._txn_conn.reset(token)


async def sqlalchemy_adapter(
    *,
    url: str = "sqlite+aiosqlite:///:memory:",
    engine: AsyncEngine | None = None,
    extra_models: Sequence[ModelDef] = (),
    create_schema: bool = True,
) -> CustomAdapter:
    """Build a SQLAlchemy adapter and materialize core + extra schema."""
    eng = engine or create_async_engine(url, future=True)
    models = tuple(CORE_MODELS) + tuple(extra_models)
    metadata = build_metadata(models)
    adapter = SQLAlchemyAdapter(engine=eng, metadata=metadata, models=models)
    if create_schema:
        async with eng.begin() as conn:
            await conn.run_sync(metadata.create_all)
    return adapter
