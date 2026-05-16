"""Field/where transforms.

Mirrors `transformInput`, `transformOutput`, `transformWhereClause` in
`reference/packages/better-auth/src/db/adapter/index.ts`. Each adapter calls these
to translate between the logical schema (what plugins see) and the physical schema
(what the database stores).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from better_auth.types.adapter import Record, Where


def transform_input(
    data: Record,
    *,
    field_map: Mapping[str, str],
) -> Record:
    """Translate a logical record to its physical column-named form."""
    return {field_map.get(k, k): v for k, v in data.items()}


def transform_output(
    data: Record | None,
    *,
    field_map: Mapping[str, str],
) -> Record | None:
    """Translate a physical record back to logical field names."""
    if data is None:
        return None
    reverse = {v: k for k, v in field_map.items()}
    return {reverse.get(k, k): v for k, v in data.items()}


def transform_where(
    where: Sequence[Where],
    *,
    field_map: Mapping[str, str],
) -> tuple[Where, ...]:
    """Translate logical field names in a where clause to physical column names."""
    return tuple(
        Where(
            field=field_map.get(w.field, w.field),
            value=w.value,
            operator=w.operator,
            connector=w.connector,
        )
        for w in where
    )
