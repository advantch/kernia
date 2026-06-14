"""Unit tests for kernia.db.migrations.codegen."""

from __future__ import annotations

import pytest
from kernia.db.migrations import emit_migration, resolve_full_schema
from kernia.db.schema import CORE_MODELS
from kernia.types.adapter import FieldDef, ModelDef
from kernia.types.plugin import PluginSchema


class _P:
    """Bare plugin shape — only the fields resolve_full_schema reads."""

    def __init__(self, id: str, schema: PluginSchema | None) -> None:
        self.id = id
        self.schema = schema


def test_core_schema_passes_through() -> None:
    out = resolve_full_schema(CORE_MODELS, [])
    assert {m.name for m in out} == {"user", "session", "account", "verification"}


def test_plugin_adds_new_table() -> None:
    new_table = ModelDef(name="invitation", fields=(FieldDef("id", "string", unique=True),))
    p = _P(id="org", schema=PluginSchema(tables=(new_table,)))
    out = resolve_full_schema(CORE_MODELS, [p])
    assert "invitation" in {m.name for m in out}


def test_plugin_extends_existing_model() -> None:
    p = _P(
        id="phone",
        schema=PluginSchema(
            extend={"user": (FieldDef("phoneNumber", "string", required=False),)},
        ),
    )
    out = resolve_full_schema(CORE_MODELS, [p])
    user = next(m for m in out if m.name == "user")
    assert any(f.name == "phoneNumber" for f in user.fields)


def test_plugin_rejects_duplicate_table_name() -> None:
    dup = ModelDef(name="user", fields=(FieldDef("id", "string"),))
    p = _P(id="bad", schema=PluginSchema(tables=(dup,)))
    with pytest.raises(ValueError, match="already exists"):
        resolve_full_schema(CORE_MODELS, [p])


def test_plugin_rejects_extending_unknown_model() -> None:
    p = _P(id="bad", schema=PluginSchema(extend={"ghost": (FieldDef("x", "string"),)}))
    with pytest.raises(ValueError, match="unknown model"):
        resolve_full_schema(CORE_MODELS, [p])


def test_plugin_rejects_redefining_field() -> None:
    p = _P(
        id="bad",
        schema=PluginSchema(extend={"user": (FieldDef("email", "string"),)}),
    )
    with pytest.raises(ValueError, match="redefine field"):
        resolve_full_schema(CORE_MODELS, [p])


def test_emit_migration_contains_create_table_for_each_model() -> None:
    src = emit_migration(CORE_MODELS, revision="abc123")
    for model in CORE_MODELS:
        assert f"op.create_table({model.name!r}" in src
    assert "def upgrade()" in src
    assert "def downgrade()" in src
    assert "revision = 'abc123'" in src
    assert "down_revision = None" in src


def test_emit_migration_with_down_revision() -> None:
    src = emit_migration(CORE_MODELS, revision="b", down_revision="a")
    assert "down_revision = 'a'" in src


def test_emit_migration_is_valid_python() -> None:
    src = emit_migration(CORE_MODELS, revision="r1")
    # The emitted source should compile (sa + op are imports the user has).
    compile(src, "<emitted>", "exec")
