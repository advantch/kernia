"""Runtime schema resolution — the `get-tables` equivalent.

Mirrors `getAuthTables` in `reference/packages/better-auth/src/db/get-tables.ts`.

At startup the core must compute the *resolved* table set: core tables, plus every
plugin's `schema.tables`, plus every plugin's `schema.extend` field additions, plus
any user-supplied `additionalFields`. The result drives:

  * the transform layer (defaults / field-name mapping / value transforms), and
  * migration codegen.

This is distinct from `db.migrations.codegen.resolve_full_schema`, which returns a
tuple for the migration emitter. `resolve_tables` returns a name-keyed mapping and
additionally folds in user `additionalFields`, so the running adapter and the
migration generator share one source of truth.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from kernia.db.schema.core_tables import CORE_MODELS
from kernia.types.adapter import FieldDef, ModelDef
from kernia.types.plugin import KerniaPlugin


def _rate_limit_model() -> ModelDef:
    """The `rateLimit` table, added when rate-limit storage is the database.

    Mirrors the `rateLimit` table in `getAuthTables` (key/count/lastRequest).
    """
    import time

    return ModelDef(
        name="rateLimit",
        fields=(
            FieldDef("key", "string", unique=True),
            FieldDef("count", "number"),
            FieldDef(
                "lastRequest",
                "number",
                bigint=True,
                default=lambda: int(time.time() * 1000),
            ),
        ),
    )


def _merge_fields(
    target: ModelDef,
    extra_fields: Sequence[FieldDef],
    *,
    source: str,
) -> ModelDef:
    """Append `extra_fields` to `target`, rejecting duplicate logical names."""
    existing = {f.name for f in target.fields}
    for f in extra_fields:
        if f.name in existing:
            raise ValueError(
                f"{source} tries to redefine field {target.name}.{f.name}"
            )
        existing.add(f.name)
    return ModelDef(
        name=target.name,
        fields=tuple(target.fields) + tuple(extra_fields),
        table_name=target.table_name,
    )


def _apply_model_override(model: ModelDef, override: Any) -> ModelDef:
    """Apply a per-model config (`modelName` / field renames) to a :class:`ModelDef`.

    `override` is duck-typed: any object exposing optional ``model_name`` (str),
    ``fields`` (logical -> physical rename map), and ``additional_fields``
    (sequence of :class:`FieldDef`). Mirrors how ``getAuthTables`` threads
    ``options.<model>.{modelName,fields,additionalFields}`` onto each table.
    """
    model_name = getattr(override, "model_name", None)
    renames: Mapping[str, str] = getattr(override, "fields", {}) or {}

    new_fields = list(model.fields)
    if renames:
        new_fields = [
            dataclasses.replace(f, field_name=renames[f.name])
            if f.name in renames
            else f
            for f in new_fields
        ]

    result = ModelDef(
        name=model.name,
        fields=tuple(new_fields),
        table_name=model_name or model.table_name,
    )

    extra = getattr(override, "additional_fields", ()) or ()
    if extra:
        result = _merge_fields(result, tuple(extra), source=f"options.{model.name}")
    return result


def resolve_tables(
    plugins: Iterable[KerniaPlugin] = (),
    *,
    core_models: Sequence[ModelDef] = CORE_MODELS,
    additional_fields: Mapping[str, Sequence[FieldDef]] | None = None,
    model_overrides: Mapping[str, Any] | None = None,
    secondary_storage: bool = False,
    store_session_in_database: bool = False,
    store_verification_in_database: bool = False,
    rate_limit_database: bool = False,
) -> dict[str, ModelDef]:
    """Compute the resolved table set.

    Order of application (later wins / extends earlier):
      1. core tables
      2. per-model overrides (`modelName` + field renames + additionalFields)
      3. plugin `schema.tables` (new tables; collision with an existing name raises)
      4. plugin `schema.extend` (field additions to existing tables)
      5. user `additional_fields` (field additions to existing tables)

    ``model_overrides`` maps a *core* logical name (``user``/``session``/
    ``account``/``verification``) to a duck-typed config object — see
    :func:`_apply_model_override`. Mirrors better-auth's ``getAuthTables``.

    When ``secondary_storage`` is set, the ``session`` and ``verification`` tables
    are excluded unless ``store_session_in_database`` / ``store_verification_in_database``
    respectively force them back in (mirrors get-tables.ts lines 202-205, 292-294).
    When ``rate_limit_database`` is set, a ``rateLimit`` table is added.

    Returns a mapping of logical model name -> :class:`ModelDef`.
    """
    by_name: dict[str, ModelDef] = {m.name: m for m in core_models}

    if secondary_storage:
        if not store_session_in_database:
            by_name.pop("session", None)
        if not store_verification_in_database:
            by_name.pop("verification", None)

    for model_name, override in (model_overrides or {}).items():
        if model_name not in by_name:
            # An override for an excluded table (e.g. session under secondary
            # storage) is a no-op rather than an error.
            continue
        by_name[model_name] = _apply_model_override(by_name[model_name], override)

    for plugin in plugins:
        schema = getattr(plugin, "schema", None)
        if schema is None:
            continue
        source = f"plugin {getattr(plugin, 'id', '?')!r}"
        for new_model in schema.tables or ():
            if new_model.name in by_name:
                raise ValueError(
                    f"{source} declared a table {new_model.name!r} that already exists"
                )
            by_name[new_model.name] = new_model
        for model_name, extra_fields in (schema.extend or {}).items():
            if model_name not in by_name:
                raise ValueError(
                    f"{source} tries to extend unknown model {model_name!r}"
                )
            by_name[model_name] = _merge_fields(
                by_name[model_name], extra_fields, source=source
            )

    for model_name, extra_fields in (additional_fields or {}).items():
        if model_name not in by_name:
            raise ValueError(
                f"additionalFields target unknown model {model_name!r}"
            )
        by_name[model_name] = _merge_fields(
            by_name[model_name], extra_fields, source="additionalFields"
        )

    if rate_limit_database and "rateLimit" not in by_name:
        by_name["rateLimit"] = _rate_limit_model()

    return by_name


__all__ = ["resolve_tables"]
