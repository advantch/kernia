"""SQLAlchemy async adapter — implements `CustomAdapter`.

Wraps an `AsyncEngine`. Builds tables from `ModelDef` so the same schema definition
that the memory adapter uses also drives Postgres/MySQL/SQLite.
"""

from __future__ import annotations

import secrets
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    and_,
    func,
    or_,
)
from sqlalchemy import delete as sa_delete
from sqlalchemy import insert as sa_insert
from sqlalchemy import select as sa_select
from sqlalchemy import update as sa_update
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from better_auth.db.schema import CORE_MODELS
from better_auth.types.adapter import (
    CustomAdapter,
    FieldDef,
    JoinConfig,
    ModelDef,
    Record,
    SortBy,
    Where,
)


def _sa_type(f: FieldDef) -> Any:
    match f.type:
        case "string" | "uuid":
            return String(255)
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
            cols.append(Column(f.name, _sa_type(f), **kwargs))
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

    def _table(self, model: str) -> Table:
        try:
            return self.metadata.tables[model]
        except KeyError:
            raise ValueError(f"unknown model: {model}") from None

    async def create(
        self,
        *,
        model: str,
        data: Record,
        select: Sequence[str] | None = None,
    ) -> Record:
        table = self._table(model)
        row = dict(data)
        row.setdefault("id", secrets.token_urlsafe(16))
        row.setdefault("createdAt", int(time.time()))
        row.setdefault("updatedAt", int(time.time()))
        async with self.engine.begin() as conn:
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
        stmt = sa_select(table).where(expr) if expr is not None else sa_select(table)
        async with self.engine.connect() as conn:
            row = (await conn.execute(stmt.limit(1))).first()
        if row is None:
            return None
        out = _row_to_dict(row, select)
        if join is not None:
            out[join.as_] = await self.find_one(
                model=join.model,
                where=(Where(field=join.foreign_field, value=out.get(join.on)),),
            )
        return out

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
        async with self.engine.connect() as conn:
            rows = (await conn.execute(stmt)).all()
        out = [_row_to_dict(r, select) for r in rows]
        if join is not None:
            for r in out:
                r[join.as_] = await self.find_one(
                    model=join.model,
                    where=(Where(field=join.foreign_field, value=r.get(join.on)),),
                )
        return out

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
        async with self.engine.begin() as conn:
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
        async with self.engine.begin() as conn:
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
        async with self.engine.begin() as conn:
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
        async with self.engine.begin() as conn:
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
        async with self.engine.connect() as conn:
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
        async with self.engine.begin() as conn:
            row = (await conn.execute(sa_select(table).where(expr).limit(1))).first()
            if row is None:
                return None
            await conn.execute(sa_delete(table).where(_column(table, "id") == row.id))
            return _row_to_dict(row, None)

    async def create_schema(self, *, models: Sequence[ModelDef]) -> None:
        self.metadata = build_metadata(list(self.models) + list(models))
        async with self.engine.begin() as conn:
            await conn.run_sync(self.metadata.create_all)


async def sqlalchemy_adapter(
    *,
    url: str = "sqlite+aiosqlite:///:memory:",
    engine: AsyncEngine | None = None,
    extra_models: Sequence[ModelDef] = (),
) -> CustomAdapter:
    """Build a SQLAlchemy adapter and materialize core + extra schema."""
    eng = engine or create_async_engine(url, future=True)
    models = tuple(CORE_MODELS) + tuple(extra_models)
    metadata = build_metadata(models)
    adapter = SQLAlchemyAdapter(engine=eng, metadata=metadata, models=models)
    async with eng.begin() as conn:
        await conn.run_sync(metadata.create_all)
    return adapter
