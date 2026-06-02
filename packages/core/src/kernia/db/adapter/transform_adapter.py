"""Schema-driven transform adapter — the Python analogue of `createAdapter`.

Mirrors the input/output transform layer in
`reference/packages/better-auth/src/db/adapter/index.ts`. It wraps a raw
:class:`~kernia.types.adapter.CustomAdapter` and, using the *resolved* table
set, applies — transparently and on every call — the per-field semantics declared
on :class:`~kernia.types.adapter.FieldDef`:

  * **defaults** — on ``create``, fill any absent field whose ``default`` is set
    (a callable default is invoked at write time);
  * **on_update** — on ``update`` / ``update_many``, refresh any field declaring
    ``on_update`` that the caller did not set explicitly (e.g. ``updatedAt``);
  * **transform.input / transform.output** — value transforms at the persistence
    boundary, each optionally async;
  * **field_name mapping** — translate logical field names to physical column
    names (and back on read), including inside ``where`` clauses and ``select``.

For any model not present in the resolved table set, every method is a pass-through
so unknown/dynamic models keep working unchanged. With the stock core schema (no
field declares ``transform``, ``on_update``, or a custom ``field_name``, and every
default is already supplied by callers) this wrapper is behaviour-neutral.

Database *hooks* are a separate layer — see :mod:`kernia.db.with_hooks`.
"""

from __future__ import annotations

import inspect
from collections.abc import Sequence
from typing import TYPE_CHECKING, Any

from kernia.types.adapter import (
    FieldDef,
    JoinConfig,
    ModelDef,
    Record,
    SortBy,
    Where,
)

if TYPE_CHECKING:
    from kernia.types.adapter import CustomAdapter


async def _maybe_await(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value


def _coerce_scalar(field_type: Any, value: Any) -> Any:
    """Coerce a single where-clause value to match the field's declared type.

    HTTP query params arrive as strings; SQL adapters silently cast, but mongo (and
    the in-memory adapter) do not. Mirrors the coercion in ``transformWhereClause``.
    Only strings are coerced; already-typed values pass through unchanged.
    """
    if not isinstance(value, str):
        return value
    if field_type == "boolean":
        lowered = value.strip().lower()
        if lowered == "true":
            return True
        if lowered == "false":
            return False
        return value
    if field_type == "number":
        try:
            return int(value)
        except ValueError:
            try:
                return float(value)
            except ValueError:
                return value
    return value


def _coerce_where_value(field_type: Any, value: Any) -> Any:
    """Coerce a where value (scalar or list, for ``in``/``not_in``) to the field type."""
    if isinstance(value, list | tuple):
        return [_coerce_scalar(field_type, v) for v in value]
    return _coerce_scalar(field_type, value)


class _ModelTransform:
    """Precomputed transform tables for one model."""

    __slots__ = ("physical_name", "to_physical", "to_logical", "fields_by_name")

    def __init__(self, model: ModelDef) -> None:
        # `table_name` is the physical name; falls back to the logical name.
        self.physical_name = model.table_name or model.name
        self.fields_by_name: dict[str, FieldDef] = {f.name: f for f in model.fields}
        self.to_physical: dict[str, str] = {
            f.name: (f.field_name or f.name) for f in model.fields
        }
        self.to_logical: dict[str, str] = {v: k for k, v in self.to_physical.items()}


class TransformAdapter:
    """Wraps a raw adapter, applying schema-driven field transforms."""

    def __init__(
        self,
        raw: CustomAdapter,
        tables: dict[str, ModelDef],
    ) -> None:
        self._raw = raw
        self._tables = tables
        self._xf: dict[str, _ModelTransform] = {
            name: _ModelTransform(model) for name, model in tables.items()
        }

    # -- transform helpers ------------------------------------------------

    def _physical_model(self, model: str) -> str:
        xf = self._xf.get(model)
        return xf.physical_name if xf else model

    async def _transform_input(
        self, model: str, data: Record, *, is_update: bool
    ) -> Record:
        xf = self._xf.get(model)
        if xf is None:
            return dict(data)
        out: Record = {}
        for key, value in data.items():
            field = xf.fields_by_name.get(key)
            if field is not None and field.transform and field.transform.input:
                value = await _maybe_await(field.transform.input(value))
            out[xf.to_physical.get(key, key)] = value
        if is_update:
            for name, field in xf.fields_by_name.items():
                if field.on_update is not None and name not in data:
                    out[xf.to_physical.get(name, name)] = field.on_update()
        else:
            for name, field in xf.fields_by_name.items():
                if name in data or field.default is None:
                    continue
                default = field.default
                out[xf.to_physical.get(name, name)] = (
                    default() if callable(default) else default
                )
        return out

    async def _transform_output(
        self, model: str, record: Record | None
    ) -> Record | None:
        if record is None:
            return None
        xf = self._xf.get(model)
        if xf is None:
            return record
        out: Record = {}
        for key, value in record.items():
            logical = xf.to_logical.get(key, key)
            field = xf.fields_by_name.get(logical)
            if field is not None and field.transform and field.transform.output:
                value = await _maybe_await(field.transform.output(value))
            out[logical] = value
        return out

    def _transform_where(
        self, model: str, where: Sequence[Where]
    ) -> tuple[Where, ...]:
        xf = self._xf.get(model)
        if xf is None:
            return tuple(where)
        out: list[Where] = []
        for w in where:
            field = xf.fields_by_name.get(w.field)
            value = (
                _coerce_where_value(field.type, w.value) if field is not None else w.value
            )
            out.append(
                Where(
                    field=xf.to_physical.get(w.field, w.field),
                    value=value,
                    operator=w.operator,
                    connector=w.connector,
                )
            )
        return tuple(out)

    def _transform_select(
        self, model: str, select: Sequence[str] | None
    ) -> list[str] | None:
        if select is None:
            return None
        xf = self._xf.get(model)
        if xf is None:
            return list(select)
        return [xf.to_physical.get(s, s) for s in select]

    # -- CustomAdapter surface -------------------------------------------

    async def create(
        self,
        *,
        model: str,
        data: Record,
        select: Sequence[str] | None = None,
    ) -> Record:
        physical = await self._transform_input(model, data, is_update=False)
        created = await self._raw.create(
            model=self._physical_model(model),
            data=physical,
            select=self._transform_select(model, select),
        )
        result = await self._transform_output(model, created)
        assert result is not None  # create always returns a row
        return result

    async def find_one(
        self,
        *,
        model: str,
        where: Sequence[Where],
        select: Sequence[str] | None = None,
        join: JoinConfig | None = None,
    ) -> Record | None:
        found = await self._raw.find_one(
            model=self._physical_model(model),
            where=self._transform_where(model, where),
            select=self._transform_select(model, select),
            join=join,
        )
        return await self._transform_output(model, found)

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
        mapped_sort = sort_by
        xf = self._xf.get(model)
        if sort_by is not None and xf is not None:
            mapped_sort = SortBy(
                field=xf.to_physical.get(sort_by.field, sort_by.field),
                direction=sort_by.direction,
            )
        rows = await self._raw.find_many(
            model=self._physical_model(model),
            where=self._transform_where(model, where),
            limit=limit,
            offset=offset,
            sort_by=mapped_sort,
            select=self._transform_select(model, select),
            join=join,
        )
        out: list[Record] = []
        for row in rows:
            transformed = await self._transform_output(model, row)
            if transformed is not None:
                out.append(transformed)
        return out

    async def update(
        self,
        *,
        model: str,
        where: Sequence[Where],
        update: Record,
    ) -> Record | None:
        physical = await self._transform_input(model, update, is_update=True)
        updated = await self._raw.update(
            model=self._physical_model(model),
            where=self._transform_where(model, where),
            update=physical,
        )
        return await self._transform_output(model, updated)

    async def update_many(
        self,
        *,
        model: str,
        where: Sequence[Where],
        update: Record,
    ) -> int:
        physical = await self._transform_input(model, update, is_update=True)
        return await self._raw.update_many(
            model=self._physical_model(model),
            where=self._transform_where(model, where),
            update=physical,
        )

    async def delete(
        self,
        *,
        model: str,
        where: Sequence[Where],
    ) -> None:
        await self._raw.delete(
            model=self._physical_model(model),
            where=self._transform_where(model, where),
        )

    async def delete_many(
        self,
        *,
        model: str,
        where: Sequence[Where],
    ) -> int:
        return await self._raw.delete_many(
            model=self._physical_model(model),
            where=self._transform_where(model, where),
        )

    async def count(
        self,
        *,
        model: str,
        where: Sequence[Where] = (),
    ) -> int:
        return await self._raw.count(
            model=self._physical_model(model),
            where=self._transform_where(model, where),
        )

    # -- optional protocols (delegate, applying output transform) --------

    async def consume_one(
        self,
        *,
        model: str,
        where: Sequence[Where],
    ) -> Record | None:
        consume = getattr(self._raw, "consume_one", None)
        if consume is None:
            raise AttributeError("underlying adapter does not support consume_one")
        consumed = await consume(
            model=self._physical_model(model),
            where=self._transform_where(model, where),
        )
        return await self._transform_output(model, consumed)

    def transaction(self) -> Any:
        tx = getattr(self._raw, "transaction", None)
        if tx is None:
            raise AttributeError("underlying adapter does not support transactions")
        return tx()

    async def create_schema(self, *, models: Sequence[ModelDef]) -> Any:
        create_schema = getattr(self._raw, "create_schema", None)
        if create_schema is None:
            raise AttributeError("underlying adapter does not support create_schema")
        return await create_schema(models=models)

    def __getattr__(self, name: str) -> Any:
        # Delegate any adapter-specific helpers we don't explicitly wrap.
        return getattr(self._raw, name)


__all__ = ["TransformAdapter"]
