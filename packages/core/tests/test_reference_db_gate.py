"""P0.7 — the Phase 0 parity gate: ported better-auth db-layer tests.

These mirror, 1:1 where possible, the contracts locked by better-auth's own
suite so the parity ledger is auditable against upstream:

  * ``reference/packages/core/src/db/test/get-tables.test.ts`` -> the ``getAuthTables``
    class below, exercised against :func:`resolve_tables`.
  * ``reference/packages/better-auth/src/db/db.test.ts`` -> the ``db`` class below,
    exercised against :class:`TransformAdapter` + :class:`WithHooks` (the Python
    analogues of ``createAdapter`` + ``getWithHooks``).

Upstream's tests drive the full HTTP signup flow via ``getTestInstance``; the
*behavioural* contract each one locks lives in the db layer, so we exercise it
there directly. The two contracts that still depend on machinery the Python core
does not yet have (``secondaryStorage``-driven verification-table exclusion, and
mongo-only where-value coercion) are recorded as ``xfail`` / ``skip`` with a reason
rather than silently dropped, so the gate honestly reports the remaining gap.
"""

from __future__ import annotations

import pytest
from better_auth.auth import init
from better_auth.db.schema.resolve import resolve_tables
from better_auth.db.with_hooks import get_with_hooks
from better_auth.types.adapter import FieldDef, Where
from better_auth.types.db_hooks import DatabaseHooksEntry, HookData, HookOp, ModelHooks
from better_auth.types.init_options import BetterAuthOptions, ModelConfig
from better_auth_memory_adapter import memory_adapter


def _fields_by_name(model):
    return {f.name: f for f in model.fields}


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


def _auth(**opts):
    raw = memory_adapter()
    return raw, init(BetterAuthOptions(database=raw, secret="x" * 32, **opts)).context


# ==========================================================================
# describe("getAuthTables")  ->  resolve_tables
# ==========================================================================


class TestGetAuthTables:
    def test_should_use_correct_field_name_for_refresh_token_expires_at(self):
        # upstream: `account: { fields: { refreshTokenExpiresAt: "custom_..." } }`.
        tables = resolve_tables(
            [],
            model_overrides={
                "account": ModelConfig(
                    fields={"refreshTokenExpiresAt": "custom_refresh_token_expires_at"}
                )
            },
        )
        f = _fields_by_name(tables["account"])["refreshTokenExpiresAt"]
        assert f.field_name == "custom_refresh_token_expires_at"

    def test_should_not_use_access_token_expires_at_name_for_refresh_token(self):
        # upstream: renaming both must not bleed one column name onto the other.
        tables = resolve_tables(
            [],
            model_overrides={
                "account": ModelConfig(
                    fields={
                        "accessTokenExpiresAt": "custom_access_token_expires_at",
                        "refreshTokenExpiresAt": "custom_refresh_token_expires_at",
                    }
                )
            },
        )
        account = _fields_by_name(tables["account"])
        assert (
            account["refreshTokenExpiresAt"].field_name
            == "custom_refresh_token_expires_at"
        )
        assert (
            account["accessTokenExpiresAt"].field_name
            == "custom_access_token_expires_at"
        )
        assert (
            account["refreshTokenExpiresAt"].field_name
            != account["accessTokenExpiresAt"].field_name
        )

    def test_should_use_default_field_names_when_no_custom_names_provided(self):
        tables = resolve_tables([])
        account = _fields_by_name(tables["account"])
        refresh = account["refreshTokenExpiresAt"]
        access = account["accessTokenExpiresAt"]
        # Python defaults field_name to None (== logical name); upstream reports the
        # logical name. Assert the effective physical name equals the logical name.
        assert (refresh.field_name or refresh.name) == "refreshTokenExpiresAt"
        assert (access.field_name or access.name) == "accessTokenExpiresAt"
        assert (refresh.field_name or refresh.name) != (
            access.field_name or access.name
        )

    def test_should_merge_additional_fields_into_verification_table_metadata(self):
        tables = resolve_tables(
            [],
            additional_fields={
                "verification": [
                    FieldDef("newField", "string", field_name="new_field")
                ]
            },
        )
        new_field = _fields_by_name(tables["verification"]).get("newField")
        assert new_field is not None
        assert new_field.field_name == "new_field"
        assert new_field.type == "string"

    def test_should_include_verification_table_when_no_secondary_storage(self):
        tables = resolve_tables([])
        assert "verification" in tables

    def test_should_exclude_verification_table_when_secondary_storage_configured(self):
        # upstream: secondaryStorage configured -> session + verification dropped.
        tables = resolve_tables([], secondary_storage=True)
        assert "verification" not in tables
        assert "session" not in tables

    def test_should_include_verification_table_when_store_in_database_is_true(self):
        # upstream: verification.storeInDatabase forces the table back in.
        tables = resolve_tables(
            [], secondary_storage=True, store_verification_in_database=True
        )
        assert "verification" in tables
        assert "session" not in tables  # session still excluded

    def test_should_add_rate_limit_table_when_storage_is_database(self):
        tables = resolve_tables([], rate_limit_database=True)
        assert "rateLimit" in tables
        rl = _fields_by_name(tables["rateLimit"])
        assert set(rl) == {"key", "count", "lastRequest"}


# ==========================================================================
# describe("db")  ->  TransformAdapter + WithHooks
# ==========================================================================


class TestDb:
    @pytest.mark.asyncio
    async def test_db_hooks(self):
        # upstream: create.before patches image="test-image"; create.after sets a flag.
        raw, ctx = _auth()
        callback = {"fired": False}

        async def before(user, _c):
            return HookData(data={**user, "image": "test-image"})

        async def after(_user, _c):
            callback["fired"] = True

        wh = get_with_hooks(
            ctx.adapter,
            ctx,
            [DatabaseHooksEntry("t", {"user": ModelHooks(create=HookOp(before, after))})],
        )
        created = await wh.create("user", _user_row())
        assert created is not None
        assert created["image"] == "test-image"
        assert callback["fired"] is True

    @pytest.mark.asyncio
    async def test_should_work_with_custom_field_names(self):
        # upstream: user.fields.email = "email_address" — the logical `email` field
        # still round-trips while the row is persisted under the physical column.
        raw, ctx = _auth(user=ModelConfig(fields={"email": "email_address"}))
        created = await ctx.adapter.create(model="user", data=_user_row(email="x@y.z"))
        # logical name on the way out
        assert created["email"] == "x@y.z"
        # physical column on the raw row
        stored = raw._tables["user"][0]
        assert stored["email_address"] == "x@y.z"
        assert "email" not in stored
        # and a where-clause on the logical field maps to the physical column
        found = await ctx.adapter.find_one(
            model="user", where=[Where(field="email", value="x@y.z")]
        )
        assert found is not None
        assert found["email"] == "x@y.z"

    @pytest.mark.asyncio
    async def test_delete_hooks(self):
        # upstream: delete.before + delete.after each called once with the entity.
        raw, ctx = _auth()
        await ctx.adapter.create(model="user", data=_user_row())
        calls = {"before": [], "after": []}

        async def before(row, _c):
            calls["before"].append(row)
            return True

        async def after(row, _c):
            calls["after"].append(row)

        wh = get_with_hooks(
            ctx.adapter,
            ctx,
            [DatabaseHooksEntry("t", {"user": ModelHooks(delete=HookOp(before, after))})],
        )
        await wh.delete("user", [Where(field="id", value="u1")])
        assert len(calls["before"]) == 1
        assert len(calls["after"]) == 1
        assert calls["before"][0]["email"] == "a@b.c"
        assert calls["after"][0]["email"] == "a@b.c"
        assert raw._tables["user"] == []

    @pytest.mark.asyncio
    async def test_delete_hooks_abort(self):
        # upstream: delete.before returns false -> after NOT called, row NOT deleted.
        raw, ctx = _auth()
        await ctx.adapter.create(model="user", data=_user_row())
        calls = {"before": 0, "after": 0}

        async def before(_row, _c):
            calls["before"] += 1
            return False

        async def after(_row, _c):
            calls["after"] += 1

        wh = get_with_hooks(
            ctx.adapter,
            ctx,
            [DatabaseHooksEntry("t", {"user": ModelHooks(delete=HookOp(before, after))})],
        )
        await wh.delete("user", [Where(field="id", value="u1")])
        assert calls["before"] == 1
        assert calls["after"] == 0  # after-hook never fired
        # the row survives the aborted delete
        assert len(raw._tables["user"]) == 1

    @pytest.mark.asyncio
    async def test_should_work_with_custom_model_names(self):
        # upstream: user.modelName='users' -> rows persist under the physical table
        # "users", while the logical model name "user" still addresses it.
        raw, ctx = _auth(user=ModelConfig(model_name="users"))
        created = await ctx.adapter.create(model="user", data=_user_row())
        assert created["id"] == "u1"  # logical API unchanged
        # physically stored under "users", not "user"
        assert "users" in raw._tables
        assert raw._tables["users"][0]["id"] == "u1"
        assert "user" not in raw._tables

    @pytest.mark.asyncio
    async def test_should_coerce_string_where_values_to_match_field_types(self):
        # upstream (mongo): HTTP query params arrive as strings; the adapter coerces
        # them to the field's schema type. The memory adapter does not silently cast,
        # so this exercises TransformAdapter._transform_where coercion directly.
        raw, ctx = _auth(
            additional_fields={"user": [FieldDef("age", "number", required=False)]}
        )
        await ctx.adapter.create(model="user", data=_user_row(age=25))

        # boolean: "false" -> False
        verified_false = await ctx.adapter.find_many(
            model="user", where=[Where(field="emailVerified", value="false")]
        )
        assert len(verified_false) == 1
        assert all(u["emailVerified"] is False for u in verified_false)

        # number: "25" -> 25
        by_age = await ctx.adapter.find_many(
            model="user", where=[Where(field="age", value="25")]
        )
        assert len(by_age) == 1
        assert by_age[0]["age"] == 25

        # number list (in): ["25","99"] -> [25, 99]
        by_age_in = await ctx.adapter.find_many(
            model="user",
            where=[Where(field="age", value=["25", "99"], operator="in")],
        )
        assert len(by_age_in) == 1
        assert by_age_in[0]["age"] == 25
