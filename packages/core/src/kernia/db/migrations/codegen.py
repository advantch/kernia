"""Alembic migration codegen from ModelDef[].

Two entry points:

  - `resolve_full_schema(core_models, plugins)` → `tuple[ModelDef, ...]`
    Merges core models + every plugin's `schema.tables` and applies every plugin's
    `schema.extend` field additions. Returns the final model list.

  - `emit_migration(models, *, revision, down_revision="None")` → str
    Emits a Python source string defining an Alembic migration with `op.create_table`
    for each model. Idempotent: each call with the same input produces the same
    output (no clocks, no random ids — caller supplies `revision`).

The emitted migration imports nothing beyond `sqlalchemy` and `alembic.op`. It's
safe to commit verbatim and apply via `alembic upgrade head`.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from kernia.types.adapter import FieldDef, ModelDef
from kernia.types.plugin import KerniaPlugin


def resolve_full_schema(
    core_models: Sequence[ModelDef],
    plugins: Iterable[KerniaPlugin],
) -> tuple[ModelDef, ...]:
    """Merge core + plugin schemas into the final ModelDef list.

    `extend` semantics: a plugin may add fields to an existing model by name. The
    new fields are appended (no replacement); duplicate field names raise.
    """
    by_name: dict[str, ModelDef] = {m.name: m for m in core_models}
    for plugin in plugins:
        schema = getattr(plugin, "schema", None)
        if schema is None:
            continue
        # new tables
        for new_model in schema.tables or ():
            if new_model.name in by_name:
                raise ValueError(
                    f"plugin {plugin.id!r} declared a table {new_model.name!r} "
                    f"that already exists"
                )
            by_name[new_model.name] = new_model
        # field extensions
        for model_name, extra_fields in (schema.extend or {}).items():
            if model_name not in by_name:
                raise ValueError(
                    f"plugin {plugin.id!r} tries to extend unknown model {model_name!r}"
                )
            target = by_name[model_name]
            existing_names = {f.name for f in target.fields}
            for f in extra_fields:
                if f.name in existing_names:
                    raise ValueError(
                        f"plugin {plugin.id!r} tries to redefine field "
                        f"{model_name}.{f.name}"
                    )
                existing_names.add(f.name)
            by_name[model_name] = ModelDef(
                name=target.name,
                fields=tuple(target.fields) + tuple(extra_fields),
            )
    return tuple(by_name.values())


def emit_migration(
    models: Sequence[ModelDef],
    *,
    revision: str,
    down_revision: str | None = None,
    message: str = "kernia schema",
) -> str:
    """Emit an Alembic migration source file as a string."""
    head = f'''"""{message}

Revision ID: {revision}
Revises: {down_revision or ""}
"""

from alembic import op
import sqlalchemy as sa


revision = {revision!r}
down_revision = {down_revision!r}
branch_labels = None
depends_on = None


def upgrade() -> None:
'''

    upgrade_body: list[str] = []
    for m in models:
        upgrade_body.append(_emit_create_table(m))

    downgrade_body: list[str] = []
    for m in reversed(models):
        downgrade_body.append(f"    op.drop_table({m.name!r})")

    foot = "\n\ndef downgrade() -> None:\n" + "\n".join(downgrade_body) + "\n"

    return head + "\n".join(upgrade_body) + foot


def _emit_create_table(model: ModelDef) -> str:
    lines: list[str] = [f"    op.create_table({model.name!r},"]
    for f in model.fields:
        lines.append(f"        {_emit_column(f)},")
    lines.append("    )")
    return "\n".join(lines)


def _emit_column(f: FieldDef) -> str:
    # Column positional args come first (name, type, optionally ForeignKey),
    # then keyword args. SQLAlchemy accepts mixed positional ForeignKey args.
    type_call = _type_call(f.type)
    positional: list[str] = [repr(f.name), type_call]
    if f.references is not None:
        ref_model, ref_field = f.references
        positional.append(f"sa.ForeignKey({ref_model + '.' + ref_field!r})")
    kw: list[str] = []
    if f.name == "id":
        kw.append("primary_key=True")
    if f.unique and f.name != "id":
        kw.append("unique=True")
    kw.append(f"nullable={not f.required}")
    if f.default is not None or f.type == "boolean":
        kw.append(f"default={f.default!r}")
    return "sa.Column(" + ", ".join(positional + kw) + ")"


def _type_call(t: str) -> str:
    return {
        "string": "sa.String(255)",
        "uuid": "sa.String(36)",
        "text": "sa.Text()",
        "number": "sa.Integer()",
        "boolean": "sa.Boolean()",
        "date": "sa.Integer()",  # unix seconds (matches the rest of the stack)
        "json": "sa.JSON()",
        "string[]": "sa.JSON()",
        "number[]": "sa.JSON()",
    }.get(t, "sa.String(255)")


__all__ = ["emit_migration", "resolve_full_schema"]
