"""Phase 0 gate tests: schema resolution, the transform adapter, and the
database-hook (`with_hooks`) runtime.

Mirrors the behaviour locked by better-auth's own `db/with-hooks` and
`db/get-tables` tests:

  * resolved tables fold in plugin tables/extends + user ``additional_fields``;
  * the transform adapter applies defaults, ``on_update``, ``transform.input``/
    ``output`` and ``field_name`` mapping transparently;
  * database hooks fire before/after, abort on ``False``, and patch on
    ``{"data": ...}``.
"""

from __future__ import annotations

from typing import ClassVar

import pytest
from kernia.auth import init
from kernia.db.hook_queue import collect_after_hooks
from kernia.db.schema.resolve import resolve_tables
from kernia.db.with_hooks import get_with_hooks
from kernia.types.adapter import FieldDef, FieldTransform, ModelDef, Where
from kernia.types.db_hooks import (
    DatabaseHooksEntry,
    HookData,
    HookOp,
    ModelHooks,
)
from kernia.types.init_options import KerniaOptions
from kernia.types.plugin import PluginSchema
from kernia_memory_adapter import memory_adapter

# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------


class _Plugin:
    """Minimal plugin exposing a schema (new table + an extend)."""

    id = "demo"
    version = None
    endpoints = None
    middlewares = None
    hooks = None
    database_hooks = None
    on_request = None
    on_response = None
    rate_limit = None
    error_codes = None
    init = None
    schema = PluginSchema(
        tables=(ModelDef(name="widget", fields=(FieldDef("id", "string", unique=True),)),),
        extend={"user": (FieldDef("plan", "string", required=False, default="free"),)},
    )


def _user_row(**over):
    base = {
        "id": "u1",
        "email": "a@b.c",
        "emailVerified": False,
        "name": "n",
        "createdAt": 0,
        "updatedAt": 0,
    }
    base.update(over)
    return base


# --------------------------------------------------------------------------
# P0.2 — schema resolution
# --------------------------------------------------------------------------


def test_resolve_tables_core_only():
    tables = resolve_tables([])
    assert set(tables) == {"user", "session", "account", "verification"}


def test_resolve_tables_folds_plugin_tables_and_extends():
    tables = resolve_tables([_Plugin()])
    assert "widget" in tables
    assert "plan" in {f.name for f in tables["user"].fields}


def test_resolve_tables_folds_additional_fields():
    tables = resolve_tables(
        [], additional_fields={"user": [FieldDef("nick", "string", required=False)]}
    )
    assert "nick" in {f.name for f in tables["user"].fields}


def test_resolve_tables_rejects_duplicate_table():
    class Dup(_Plugin):
        schema = PluginSchema(
            tables=(ModelDef(name="user", fields=(FieldDef("id", "string"),)),)
        )

    with pytest.raises(ValueError, match="already exists"):
        resolve_tables([Dup()])


def test_resolve_tables_rejects_extend_unknown_model():
    class Bad(_Plugin):
        schema = PluginSchema(extend={"nope": (FieldDef("x", "string"),)})

    with pytest.raises(ValueError, match="unknown model"):
        resolve_tables([Bad()])


# --------------------------------------------------------------------------
# P0.3a — transform adapter (via init so it's the real wiring)
# --------------------------------------------------------------------------


def _auth_with(**opts):
    raw = memory_adapter()
    handle = init(KerniaOptions(database=raw, secret="x" * 32, **opts))
    return raw, handle.context


@pytest.mark.asyncio
async def test_transform_field_name_mapping_and_value_transforms():
    raw, ctx = _auth_with(
        additional_fields={
            "user": [
                FieldDef(
                    "nick",
                    "string",
                    required=False,
                    field_name="nickname",
                    transform=FieldTransform(
                        input=lambda v: v.upper(), output=lambda v: v.lower()
                    ),
                )
            ]
        }
    )
    created = await ctx.adapter.create(model="user", data=_user_row(nick="Bob"))
    # output transform lowercases what we read back
    assert created["nick"] == "bob"
    stored = raw._tables["user"][0]
    # physical column is `nickname`, value was uppercased on the way in
    assert stored["nickname"] == "BOB"
    assert "nick" not in stored

    # select maps logical -> physical, and the read-back value is output-transformed.
    # (Matching better-auth: where *values* are NOT run through transform.input, only
    # the column name is mapped — so we query by id, not by the transformed field.)
    found = await ctx.adapter.find_one(
        model="user", where=[Where(field="id", value="u1")], select=["nick"]
    )
    assert found == {"nick": "bob"}


@pytest.mark.asyncio
async def test_transform_applies_defaults_on_create_only_for_absent_fields():
    raw, ctx = _auth_with(
        additional_fields={
            "user": [FieldDef("plan", "string", required=False, default="free")]
        }
    )
    # absent -> default filled
    await ctx.adapter.create(model="user", data=_user_row(id="u1"))
    assert raw._tables["user"][0]["plan"] == "free"
    # present -> caller value preserved
    await ctx.adapter.create(model="user", data=_user_row(id="u2", email="z@z.z", plan="pro"))
    assert raw._tables["user"][1]["plan"] == "pro"


@pytest.mark.asyncio
async def test_transform_on_update_refreshes_absent_field():
    bumps = iter([111, 222])
    raw, ctx = _auth_with(
        additional_fields={
            "user": [
                FieldDef("rev", "number", required=False, on_update=lambda: next(bumps))
            ]
        }
    )
    await ctx.adapter.create(model="user", data=_user_row())
    await ctx.adapter.update(
        model="user", where=[Where(field="id", value="u1")], update={"name": "n2"}
    )
    assert raw._tables["user"][0]["rev"] == 111
    # explicit value wins over on_update factory
    await ctx.adapter.update(
        model="user", where=[Where(field="id", value="u1")], update={"rev": 999}
    )
    assert raw._tables["user"][0]["rev"] == 999


@pytest.mark.asyncio
async def test_transform_passes_through_unknown_model():
    raw, ctx = _auth_with()
    row = await ctx.adapter.create(model="adhoc", data={"id": "x", "k": "v"})
    # pass-through: the wrapper adds nothing; the memory adapter supplies its own
    # createdAt/updatedAt, so assert the input survives unchanged.
    assert row["id"] == "x" and row["k"] == "v"


# --------------------------------------------------------------------------
# P0.3b — database hooks (with_hooks)
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_database_hooks_before_after_and_patch():
    raw, ctx = _auth_with()
    seen = {"before": 0, "after": 0, "after_row": None}

    async def before(data, _ctx):
        seen["before"] += 1
        return HookData(data={"name": "patched"})

    async def after(row, _ctx):
        seen["after"] += 1
        seen["after_row"] = row

    wh = get_with_hooks(
        ctx.adapter,
        ctx,
        [DatabaseHooksEntry("t", {"user": ModelHooks(create=HookOp(before, after))})],
    )
    out = await wh.create("user", _user_row(name="orig"))
    assert out["name"] == "patched"
    assert seen["before"] == 1 and seen["after"] == 1
    assert seen["after_row"]["name"] == "patched"


@pytest.mark.asyncio
async def test_database_hook_abort_on_false_skips_write():
    raw, ctx = _auth_with()

    async def deny(_data, _ctx):
        return False

    wh = get_with_hooks(
        ctx.adapter,
        ctx,
        [DatabaseHooksEntry("t", {"user": ModelHooks(create=HookOp(before=deny))})],
    )
    res = await wh.create("user", _user_row())
    assert res is None
    assert raw._tables.get("user", []) == []


@pytest.mark.asyncio
async def test_delete_hooks_receive_entity():
    raw, ctx = _auth_with()
    await ctx.adapter.create(model="user", data=_user_row())
    captured = {}

    async def before(row, _ctx):
        captured["before"] = row

    async def after(row, _ctx):
        captured["after"] = row

    wh = get_with_hooks(
        ctx.adapter,
        ctx,
        [DatabaseHooksEntry("t", {"user": ModelHooks(delete=HookOp(before, after))})],
    )
    await wh.delete("user", [Where(field="id", value="u1")])
    assert captured["before"]["email"] == "a@b.c"
    assert captured["after"]["email"] == "a@b.c"
    assert raw._tables["user"] == []


@pytest.mark.asyncio
async def test_after_hooks_defer_until_queue_drains():
    raw, ctx = _auth_with()
    order = []

    async def after(_row, _ctx):
        order.append("after")

    wh = get_with_hooks(
        ctx.adapter,
        ctx,
        [DatabaseHooksEntry("t", {"user": ModelHooks(create=HookOp(after=after))})],
    )
    with collect_after_hooks() as queue:
        await wh.create("user", _user_row())
        order.append("write-done")
        # after-hook is deferred, not yet run
        assert order == ["write-done"]
    # drain the queue (what a committed transaction will do in P0.4)
    for fn in queue:
        await fn()
    assert order == ["write-done", "after"]


@pytest.mark.asyncio
async def test_init_collects_options_and_plugin_database_hooks():
    calls = []

    async def opt_before(data, _ctx):
        calls.append("opt")

    class HookPlugin(_Plugin):
        id = "hooky"
        schema = None
        database_hooks: ClassVar = {
            "user": ModelHooks(create=HookOp(before=lambda d, c: calls.append("plugin")))
        }

    raw = memory_adapter()
    handle = init(
        KerniaOptions(
            database=raw,
            secret="x" * 32,
            plugins=[HookPlugin()],
            database_hooks={"user": ModelHooks(create=HookOp(before=opt_before))},
        )
    )
    ctx = handle.context
    # options entry first, then plugin entry
    assert [e.source for e in ctx.database_hooks] == ["options", "hooky"]
    await ctx.with_hooks.create("user", _user_row())
    assert calls == ["opt", "plugin"]
