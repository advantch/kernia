"""Adapter factory.

Mirrors `createAdapter` in `reference/packages/better-auth/src/db/adapter/index.ts`.
Wraps a raw `CustomAdapter` with the canonical model registry so plugins can refer to
logical model names while adapters see their concrete (possibly remapped) names.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from kernia.types.adapter import CustomAdapter, ModelDef


@dataclass(frozen=True, slots=True)
class AdapterContext:
    """Resolved adapter context: maps logical model names to physical and field
    names to physical column names. Filled at startup from core + plugin schemas."""

    adapter: CustomAdapter
    model_names: Mapping[str, str]  # logical → physical
    field_names: Mapping[str, Mapping[str, str]]  # model → {logical: physical}


def create_adapter(
    adapter: CustomAdapter,
    *,
    models: tuple[ModelDef, ...],
    rename_models: Mapping[str, str] | None = None,
    rename_fields: Mapping[str, Mapping[str, str]] | None = None,
) -> AdapterContext:
    """Construct an `AdapterContext` from a raw adapter + the resolved model list.

    `rename_models` lets the user re-map logical names ("user" → "app_user") for
    integration with existing schemas. Same for `rename_fields`. Validation that
    every model in `models` has a unique name + non-empty fields happens here.
    """
    seen: set[str] = set()
    for m in models:
        if m.name in seen:
            raise ValueError(f"Duplicate model name in schema: {m.name!r}")
        if not m.fields:
            raise ValueError(f"Model {m.name!r} has no fields")
        seen.add(m.name)

    model_names: dict[str, str] = {
        m.name: (rename_models or {}).get(m.name, m.name) for m in models
    }
    field_names: dict[str, dict[str, str]] = {}
    for m in models:
        per = (rename_fields or {}).get(m.name, {})
        field_names[m.name] = {f.name: per.get(f.name, f.name) for f in m.fields}

    return AdapterContext(adapter=adapter, model_names=model_names, field_names=field_names)
