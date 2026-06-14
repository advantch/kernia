"""MongoDB adapter — implements `CustomAdapter`, `ConsumingAdapter`, `SchemaAdapter`.

Wraps `motor.motor_asyncio.AsyncIOMotorClient`. Stores the better-auth `id` field
in MongoDB's `_id` column and translates between them transparently so callers never
see the underlying naming.

Mirrors `reference/packages/mongo-adapter/src/mongodb-adapter.ts`.
"""

from __future__ import annotations

import re
import secrets
import time
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from kernia.db.schema import CORE_MODELS
from kernia.types.adapter import (
    ConsumingAdapter,
    CustomAdapter,
    FieldDef,
    JoinConfig,
    ModelDef,
    Record,
    SchemaAdapter,
    SortBy,
    Where,
)

# ---------------------------------------------------------------------------
# WhereOp -> BSON filter translator (pure function — heavily unit-tested)
# ---------------------------------------------------------------------------


_REGEX_META = re.compile(r"[.\*\+\?\^\$\{\}\(\)\|\[\]\\]")


def _escape_regex(s: str, max_length: int = 256) -> str:
    """Escape regex special chars for safe `$regex` use."""
    return _REGEX_META.sub(lambda m: "\\" + m.group(0), s[:max_length])


def _field_name(field: str) -> str:
    """Map adapter-facing field names to MongoDB column names.

    Only `id` is renamed (to `_id`); everything else is passed through.
    """
    return "_id" if field == "id" else field


def _clause_to_bson(clause: Where) -> dict[str, Any]:
    """Translate one Where clause to a MongoDB filter fragment."""
    field = _field_name(clause.field)
    val = clause.value
    op = clause.operator
    match op:
        case "eq":
            return {field: val}
        case "ne":
            return {field: {"$ne": val}}
        case "lt":
            return {field: {"$lt": val}}
        case "lte":
            return {field: {"$lte": val}}
        case "gt":
            return {field: {"$gt": val}}
        case "gte":
            return {field: {"$gte": val}}
        case "in":
            return {field: {"$in": list(val)}}
        case "not_in":
            return {field: {"$nin": list(val)}}
        case "contains":
            return {field: {"$regex": f".*{_escape_regex(str(val))}.*"}}
        case "starts_with":
            return {field: {"$regex": f"^{_escape_regex(str(val))}"}}
        case "ends_with":
            return {field: {"$regex": f"{_escape_regex(str(val))}$"}}
        case "ilike_eq":
            return {field: {"$regex": f"^{_escape_regex(str(val))}$", "$options": "i"}}
        case _:  # pragma: no cover
            raise ValueError(f"unsupported operator: {op}")


def where_to_bson(where: Sequence[Where]) -> dict[str, Any]:
    """Translate a Sequence[Where] into a complete BSON filter.

    Groups by connector — clauses with connector="AND" go under `$and`, those with
    "OR" under `$or`. The first clause's connector is ignored (it has no left side).
    A single clause is emitted bare without wrapping.
    """
    if not where:
        return {}
    if len(where) == 1:
        return _clause_to_bson(where[0])
    and_parts: list[dict[str, Any]] = []
    or_parts: list[dict[str, Any]] = []
    for i, clause in enumerate(where):
        frag = _clause_to_bson(clause)
        # First clause has no connector context — treat as AND.
        if i == 0 or clause.connector == "AND":
            and_parts.append(frag)
        else:
            or_parts.append(frag)
    out: dict[str, Any] = {}
    if and_parts:
        out["$and"] = and_parts
    if or_parts:
        out["$or"] = or_parts
    return out


# ---------------------------------------------------------------------------
# Id <-> _id transparent mapping
# ---------------------------------------------------------------------------


def _to_mongo(data: Record) -> Record:
    """Map adapter-facing `id` to MongoDB `_id` on insert/update."""
    if "id" not in data:
        return dict(data)
    out = dict(data)
    out["_id"] = out.pop("id")
    return out


def _from_mongo(doc: dict[str, Any] | None) -> Record | None:
    """Map MongoDB `_id` to adapter-facing `id` on read."""
    if doc is None:
        return None
    out = dict(doc)
    if "_id" in out:
        out["id"] = out.pop("_id")
    return out


def _project(row: Record, select: Sequence[str] | None) -> Record:
    if not select:
        return row
    return {k: row[k] for k in select if k in row}


# ---------------------------------------------------------------------------
# Adapter
# ---------------------------------------------------------------------------


@dataclass
class MongoAdapter:
    """Motor-backed adapter."""

    db: Any  # AsyncIOMotorDatabase — typed as Any to avoid hard dep at type-check time
    models: tuple[ModelDef, ...] = ()

    def _coll(self, model: str) -> Any:
        return self.db[model]

    async def create(
        self,
        *,
        model: str,
        data: Record,
        select: Sequence[str] | None = None,
    ) -> Record:
        row = dict(data)
        row.setdefault("id", secrets.token_urlsafe(16))
        row.setdefault("createdAt", int(time.time()))
        row.setdefault("updatedAt", int(time.time()))
        doc = _to_mongo(row)
        await self._coll(model).insert_one(doc)
        out = _from_mongo(doc)
        assert out is not None
        return _project(out, select)

    async def find_one(
        self,
        *,
        model: str,
        where: Sequence[Where],
        select: Sequence[str] | None = None,
        join: JoinConfig | None = None,
    ) -> Record | None:
        filt = where_to_bson(where)
        doc = await self._coll(model).find_one(filt)
        out = _from_mongo(doc)
        if out is None:
            return None
        result = _project(out, select)
        if join is not None:
            foreign = await self.find_one(
                model=join.model,
                where=(Where(field=join.foreign_field, value=out.get(join.on)),),
            )
            result[join.as_] = foreign
        return result

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
        filt = where_to_bson(where)
        cursor = self._coll(model).find(filt)
        if sort_by is not None:
            mongo_field = _field_name(sort_by.field)
            direction = -1 if sort_by.direction == "desc" else 1
            cursor = cursor.sort(mongo_field, direction)
        if offset:
            cursor = cursor.skip(offset)
        if limit is not None:
            cursor = cursor.limit(limit)
        docs = await cursor.to_list(length=limit if limit is not None else None)
        out: list[Record] = []
        for d in docs:
            row = _from_mongo(d)
            assert row is not None
            row = _project(row, select)
            if join is not None:
                row[join.as_] = await self.find_one(
                    model=join.model,
                    where=(Where(field=join.foreign_field, value=row.get(join.on)),),
                )
            out.append(row)
        return out

    async def update(
        self,
        *,
        model: str,
        where: Sequence[Where],
        update: Record,
    ) -> Record | None:
        filt = where_to_bson(where)
        patch = dict(update)
        patch["updatedAt"] = int(time.time())
        doc = await self._coll(model).find_one_and_update(
            filt,
            {"$set": patch},
            return_document=True,  # ReturnDocument.AFTER
        )
        # Motor uses pymongo.ReturnDocument; True == AFTER (1)
        return _from_mongo(doc)

    async def update_many(
        self,
        *,
        model: str,
        where: Sequence[Where],
        update: Record,
    ) -> int:
        filt = where_to_bson(where)
        patch = dict(update)
        patch["updatedAt"] = int(time.time())
        result = await self._coll(model).update_many(filt, {"$set": patch})
        return int(result.modified_count)

    async def delete(
        self,
        *,
        model: str,
        where: Sequence[Where],
    ) -> None:
        filt = where_to_bson(where)
        await self._coll(model).delete_one(filt)

    async def delete_many(
        self,
        *,
        model: str,
        where: Sequence[Where],
    ) -> int:
        filt = where_to_bson(where)
        result = await self._coll(model).delete_many(filt)
        return int(result.deleted_count)

    async def count(
        self,
        *,
        model: str,
        where: Sequence[Where] = (),
    ) -> int:
        filt = where_to_bson(where)
        return int(await self._coll(model).count_documents(filt))

    async def consume_one(
        self,
        *,
        model: str,
        where: Sequence[Where],
    ) -> Record | None:
        filt = where_to_bson(where)
        doc = await self._coll(model).find_one_and_delete(filt)
        return _from_mongo(doc)

    async def create_schema(self, *, models: Sequence[ModelDef]) -> None:
        """Create indexes for fields marked unique.

        MongoDB itself creates collections on first insert, so we only need to
        materialize the unique constraints up-front. `_id` is implicitly unique.
        """
        for model in models:
            for f in model.fields:
                if not f.unique:
                    continue
                if f.name == "id":
                    continue  # _id is unique by Mongo's contract
                await self._coll(model.name).create_index(f.name, unique=True)


# Reference the optional Protocols to keep them in the package's import graph and
# make explicit which contracts MongoAdapter satisfies.
_PROTOCOLS: tuple[type, ...] = (CustomAdapter, ConsumingAdapter, SchemaAdapter)


async def mongo_adapter(
    *,
    url: str,
    db_name: str = "kernia",
    extra_models: Sequence[ModelDef] = (),
    **kwargs: Any,
) -> CustomAdapter:
    """Build a MongoDB adapter, connect, and materialize core indexes.

    `url` is a standard `mongodb://` URI. `db_name` selects the database within
    the cluster. Any additional `kwargs` are forwarded to `AsyncIOMotorClient`.
    """
    from motor.motor_asyncio import AsyncIOMotorClient  # local import — optional dep

    client = AsyncIOMotorClient(url, **kwargs)
    db = client[db_name]
    models = tuple(CORE_MODELS) + tuple(extra_models)
    adapter = MongoAdapter(db=db, models=models)
    await adapter.create_schema(models=models)
    return adapter


# Re-exported helper for FieldDef introspection — used by tests.
def is_unique_field(f: FieldDef) -> bool:
    return f.unique
