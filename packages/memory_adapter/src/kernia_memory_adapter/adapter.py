"""Pure-Python in-memory adapter — implements `CustomAdapter`.

Useful as the deterministic oracle for the adapter-conformance suite. Not durable;
state vanishes when the process exits. All operations are O(n) over the table for
simplicity; we trade speed for code clarity at this layer.

Mirrors `reference/packages/better-auth/src/adapters/memory-adapter/index.ts`.
"""

from __future__ import annotations

import contextlib
import secrets
import time
from collections.abc import AsyncIterator, Sequence
from dataclasses import dataclass, field

from kernia.types.adapter import (
    CustomAdapter,
    JoinConfig,
    Record,
    SortBy,
    Where,
)


def _match(row: Record, where: Sequence[Where]) -> bool:
    """Evaluate a where clause against a row. Honors AND/OR connectors left-to-right.

    Better Auth's TypeScript implementation has the same left-to-right semantics —
    no precedence between AND/OR. Tests in `e2e/adapter/` lock this in.
    """
    if not where:
        return True
    # Initialize accumulator to True so the first clause's connector is irrelevant.
    acc: bool | None = None
    for clause in where:
        cell = row.get(clause.field)
        op = clause.operator
        val = clause.value
        match op:
            case "eq":
                ok = cell == val
            case "ne":
                ok = cell != val
            case "lt":
                ok = cell is not None and cell < val
            case "lte":
                ok = cell is not None and cell <= val
            case "gt":
                ok = cell is not None and cell > val
            case "gte":
                ok = cell is not None and cell >= val
            case "in":
                ok = cell in val
            case "not_in":
                ok = cell not in val
            case "contains":
                ok = isinstance(cell, str) and val in cell
            case "starts_with":
                ok = isinstance(cell, str) and cell.startswith(val)
            case "ends_with":
                ok = isinstance(cell, str) and cell.endswith(val)
            case "ilike_eq":
                ok = (
                    isinstance(cell, str)
                    and isinstance(val, str)
                    and cell.lower() == val.lower()
                )
            case _:  # pragma: no cover — exhaustive
                raise ValueError(f"unsupported operator: {op}")

        if acc is None:
            acc = ok
        elif clause.connector == "AND":
            acc = acc and ok
        else:
            acc = acc or ok
    return bool(acc)


def _project(row: Record, select: Sequence[str] | None) -> Record:
    if not select:
        return dict(row)
    return {k: row[k] for k in select if k in row}


@dataclass
class MemoryAdapter:
    """In-memory adapter. One dict-of-list per model."""

    _tables: dict[str, list[Record]] = field(default_factory=dict)

    def _table(self, model: str) -> list[Record]:
        return self._tables.setdefault(model, [])

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
        self._table(model).append(row)
        return _project(row, select)

    async def find_one(
        self,
        *,
        model: str,
        where: Sequence[Where],
        select: Sequence[str] | None = None,
        join: JoinConfig | None = None,
    ) -> Record | None:
        for row in self._table(model):
            if _match(row, where):
                out = _project(row, select)
                if join is not None:
                    foreign = await self.find_one(
                        model=join.model,
                        where=(Where(field=join.foreign_field, value=row.get(join.on)),),
                    )
                    out[join.as_] = foreign
                return out
        return None

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
        rows = [row for row in self._table(model) if _match(row, where)]
        if sort_by is not None:
            rows = sorted(
                rows,
                key=lambda r: (r.get(sort_by.field) is None, r.get(sort_by.field)),
                reverse=sort_by.direction == "desc",
            )
        if offset:
            rows = rows[offset:]
        if limit is not None:
            rows = rows[:limit]
        out = [_project(r, select) for r in rows]
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
        for row in self._table(model):
            if _match(row, where):
                row.update(update)
                row["updatedAt"] = int(time.time())
                return dict(row)
        return None

    async def update_many(
        self,
        *,
        model: str,
        where: Sequence[Where],
        update: Record,
    ) -> int:
        n = 0
        for row in self._table(model):
            if _match(row, where):
                row.update(update)
                row["updatedAt"] = int(time.time())
                n += 1
        return n

    async def delete(
        self,
        *,
        model: str,
        where: Sequence[Where],
    ) -> None:
        table = self._table(model)
        for i, row in enumerate(table):
            if _match(row, where):
                del table[i]
                return

    async def delete_many(
        self,
        *,
        model: str,
        where: Sequence[Where],
    ) -> int:
        table = self._table(model)
        keep = [r for r in table if not _match(r, where)]
        removed = len(table) - len(keep)
        table[:] = keep
        return removed

    async def count(
        self,
        *,
        model: str,
        where: Sequence[Where] = (),
    ) -> int:
        return sum(1 for row in self._table(model) if _match(row, where))

    async def consume_one(
        self,
        *,
        model: str,
        where: Sequence[Where],
    ) -> Record | None:
        table = self._table(model)
        for i, row in enumerate(table):
            if _match(row, where):
                del table[i]
                return dict(row)
        return None

    @contextlib.asynccontextmanager
    async def transaction(self) -> AsyncIterator[None]:
        """No-op transaction support.

        The in-memory adapter has no persistence layer, so transactions cannot be
        meaningfully rolled back. The context manager is provided so callers can
        write adapter-agnostic code; tests that need real rollback semantics must
        run against SQLAlchemy or MongoDB.
        """
        yield


def memory_adapter() -> CustomAdapter:
    """Construct a fresh in-memory adapter."""
    return MemoryAdapter()
