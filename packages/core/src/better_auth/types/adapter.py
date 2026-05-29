"""Adapter contract — mirrors `reference/packages/better-auth/src/types/adapter.ts`.

Every database adapter (memory, SQLAlchemy, Drizzle-equivalent, etc.) implements
`CustomAdapter`. The core never calls a database directly; it only calls these methods.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Sequence
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass
from typing import Any, Literal, Protocol, runtime_checkable

# ---------------------------------------------------------------------------
# Where clause — mirrors `CleanedWhere` in adapter.ts
# ---------------------------------------------------------------------------

WhereOperator = Literal[
    "eq",
    "ne",
    "lt",
    "lte",
    "gt",
    "gte",
    "in",
    "not_in",
    "contains",
    "starts_with",
    "ends_with",
    "ilike_eq",
]

WhereConnector = Literal["AND", "OR"]


@dataclass(frozen=True, slots=True)
class Where:
    """A single where-clause clause.

    Mirrors the TS shape:
        { field: string; value: Value; operator?: "eq"|...; connector?: "AND"|"OR" }
    """

    field: str
    value: Any
    operator: WhereOperator = "eq"
    connector: WhereConnector = "AND"


@dataclass(frozen=True, slots=True)
class SortBy:
    """Sort directive. Mirrors `{ field: string; direction: "asc" | "desc" }`."""

    field: str
    direction: Literal["asc", "desc"] = "asc"


@dataclass(frozen=True, slots=True)
class JoinConfig:
    """Eager-load directive for an adapter that supports joins.

    Adapters that cannot natively join (e.g. document stores) may emulate this by
    issuing follow-up reads. The core makes no assumption about how the join is
    realized — only that the resulting record contains the requested field.
    """

    model: str
    on: str  # local field name
    foreign_field: str
    as_: str  # alias on the returned record


# ---------------------------------------------------------------------------
# Model schema — passed to `create_schema` for codegen / migrations
# ---------------------------------------------------------------------------

FieldType = Literal[
    "string",
    "number",
    "boolean",
    "date",
    "json",
    "uuid",
    "text",
    "string[]",
    "number[]",
]


OnDeleteAction = Literal[
    "no action",
    "restrict",
    "cascade",
    "set null",
    "set default",
]

# A default may be a static primitive or a zero-arg factory (called at create time).
DefaultValue = Any | Callable[[], Any]


@dataclass(frozen=True, slots=True)
class FieldTransform:
    """Value transforms applied at the persistence boundary.

    Mirrors JS `transform: { input?, output? }`. `input` runs before a value is
    written to the adapter; `output` runs after a value is read back. Either may be
    sync or async.
    """

    input: Callable[[Any], Awaitable[Any] | Any] | None = None
    output: Callable[[Any], Awaitable[Any] | Any] | None = None


@dataclass(frozen=True, slots=True)
class FieldDef:
    """Single column on a model. Mirrors better-auth's `DBFieldAttribute`.

    The first six attributes are the original Python surface (kept positionally
    stable so existing call sites do not break). The remainder mirror the rest of
    JS `DBFieldAttributeConfig` and are load-bearing for `additionalFields`
    semantics and the internal-adapter's input/output field filtering:

    - ``returned``: include this field in response bodies (``False`` hides secrets
      such as hashed columns).
    - ``input``: accept a client-supplied value when creating (``False`` blocks it).
    - ``transform``: input/output value transforms at the persistence boundary.
    - ``on_update``: factory invoked to refresh the value on every update
      (e.g. ``updatedAt``).
    - ``field_name``: physical column name when it differs from the logical name.
    - ``bigint`` / ``sortable`` / ``index`` / ``on_delete``: adapter/DDL hints.
    """

    name: str
    type: FieldType
    required: bool = True
    unique: bool = False
    references: tuple[str, str] | None = None  # (model, field)
    default: DefaultValue = None
    # --- extended attributes (mirror JS DBFieldAttributeConfig) ---
    returned: bool = True
    input: bool = True
    transform: FieldTransform | None = None
    on_update: Callable[[], Any] | None = None
    field_name: str | None = None
    bigint: bool = False
    sortable: bool = False
    index: bool = False
    on_delete: OnDeleteAction = "cascade"


@dataclass(frozen=True, slots=True)
class ModelDef:
    """A logical table definition that an adapter materializes.

    ``name`` is the *logical* model name (the key the core, plugins, and the API
    address the model by). ``table_name`` is the *physical* name the adapter
    persists under; when ``None`` it equals ``name``. Mirrors better-auth's
    ``modelName`` override (``options.user.modelName`` etc.).
    """

    name: str
    fields: tuple[FieldDef, ...]
    table_name: str | None = None


# ---------------------------------------------------------------------------
# The adapter Protocol
# ---------------------------------------------------------------------------

Record = dict[str, Any]


@runtime_checkable
class CustomAdapter(Protocol):
    """The contract every adapter must satisfy.

    Method signatures mirror `reference/packages/better-auth/src/db/internal-adapter.ts`
    and `reference/packages/better-auth/src/adapters/`. Adapters MUST NOT throw on a
    missing record from `find_one` — return `None` instead.
    """

    # Required CRUD

    async def create(
        self,
        *,
        model: str,
        data: Record,
        select: Sequence[str] | None = None,
    ) -> Record: ...

    async def find_one(
        self,
        *,
        model: str,
        where: Sequence[Where],
        select: Sequence[str] | None = None,
        join: JoinConfig | None = None,
    ) -> Record | None: ...

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
    ) -> list[Record]: ...

    async def update(
        self,
        *,
        model: str,
        where: Sequence[Where],
        update: Record,
    ) -> Record | None: ...

    async def update_many(
        self,
        *,
        model: str,
        where: Sequence[Where],
        update: Record,
    ) -> int: ...

    async def delete(
        self,
        *,
        model: str,
        where: Sequence[Where],
    ) -> None: ...

    async def delete_many(
        self,
        *,
        model: str,
        where: Sequence[Where],
    ) -> int: ...

    async def count(
        self,
        *,
        model: str,
        where: Sequence[Where] = (),
    ) -> int: ...


@runtime_checkable
class ConsumingAdapter(Protocol):
    """Optional: atomic single-row consumption (used by verification tokens, etc.)."""

    async def consume_one(
        self,
        *,
        model: str,
        where: Sequence[Where],
    ) -> Record | None: ...


@runtime_checkable
class SchemaAdapter(Protocol):
    """Optional: adapters that can materialize their own schema."""

    async def create_schema(self, *, models: Sequence[ModelDef]) -> None: ...


@runtime_checkable
class TransactionalAdapter(Protocol):
    """Optional: adapters that support atomic transactions.

    `transaction()` returns an async context manager. Operations performed on the
    adapter inside `async with adapter.transaction():` commit on clean exit and
    roll back if the block raises.

    Adapters that cannot meaningfully provide atomicity (e.g. in-memory) MAY
    implement this as a no-op so the same code path works in tests.
    """

    def transaction(self) -> AbstractAsyncContextManager[None]: ...
