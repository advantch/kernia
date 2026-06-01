"""P0.5 — plugin lifecycle wiring.

Locks the two behaviours the previous fire-and-forget `init()` got wrong:

  * plugin `init` is *deferred* (not fire-and-forget) when `init()` runs inside a
    running event loop, and `ctx.ensure_initialized()` runs it exactly once;
  * a plugin `init` that returns an :class:`InitResult` has its
    ``options_patch`` / ``context_patch`` applied to the live context.
"""

from __future__ import annotations

import pytest
from kernia.auth import init
from kernia.types.init_options import KerniaOptions
from kernia.types.plugin import InitResult
from kernia_memory_adapter import memory_adapter


class _Plugin:
    """Structural plugin; `init` records that it ran and optionally patches ctx."""

    def __init__(self, *, returns: InitResult | None = None, marker: str = "ran"):
        self.id = "lifecycle"
        self.version = None
        self.schema = None
        self.endpoints = None
        self.middlewares = None
        self.hooks = None
        self.database_hooks = None
        self.on_request = None
        self.on_response = None
        self.rate_limit = None
        self.error_codes = None
        self._returns = returns
        self._marker = marker

    async def init(self, ctx):
        ctx.plugin_state["initialized"] = self._marker
        return self._returns


def _opts(plugin):
    return KerniaOptions(database=memory_adapter(), secret="x" * 32, plugins=[plugin])


def test_init_runs_eagerly_when_no_loop():
    # Called from sync context (no running loop) -> init runs to completion.
    handle = init(_opts(_Plugin()))
    assert handle.context.plugin_state.get("initialized") == "ran"
    assert handle.context._init_done is True


@pytest.mark.asyncio
async def test_init_is_deferred_inside_running_loop():
    # Built inside a running loop -> plugin init must NOT have run yet.
    handle = init(_opts(_Plugin()))
    ctx = handle.context
    assert ctx._init_done is False
    assert "initialized" not in ctx.plugin_state
    # ensure_initialized runs it...
    await ctx.ensure_initialized()
    assert ctx.plugin_state["initialized"] == "ran"
    assert ctx._init_done is True


@pytest.mark.asyncio
async def test_ensure_initialized_is_idempotent():
    runs = {"n": 0}

    class Counter(_Plugin):
        async def init(self, ctx):
            runs["n"] += 1
            return None

    handle = init(_opts(Counter()))
    ctx = handle.context
    await ctx.ensure_initialized()
    await ctx.ensure_initialized()
    assert runs["n"] == 1


@pytest.mark.asyncio
async def test_init_result_patches_options_and_context():
    plugin = _Plugin(
        returns=InitResult(
            options_patch={"base_url": "https://patched.example"},
            context_patch={"secret": "patched-secret", "extra": "parked"},
        )
    )
    handle = init(_opts(plugin))
    ctx = handle.context
    await ctx.ensure_initialized()
    # known option attribute is set directly
    assert ctx.options.base_url == "https://patched.example"
    # known context attribute is set directly; unknown key lands in plugin_state
    assert ctx.secret == "patched-secret"
    assert ctx.plugin_state["extra"] == "parked"
