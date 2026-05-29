"""Anonymous, opt-in usage telemetry.

Mirrors `reference/packages/telemetry/`. Off by default: the plugin is the opt-in
signal — adding it to `BetterAuthOptions.plugins` enables emission. When opted in,
the plugin emits a single startup event with: better-auth-python version,
registered plugin ids, adapter kind. No PII.

`BetterAuthOptions.advanced["telemetry"] = False` force-suppresses emission even
when the plugin is present.

Implementation is intentionally minimal — events go to stdout JSON-lines unless a
custom sink is supplied. Production users can wire their own sink to forward to
PostHog/Mixpanel/etc.
"""

from __future__ import annotations

import json
import sys
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

TelemetrySink = Callable[[dict[str, Any]], Awaitable[None]]


async def _stdout_sink(event: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps({"telemetry": event}) + "\n")
    sys.stdout.flush()


@dataclass(frozen=True, slots=True)
class _TelemetryPlugin:
    id: str = "telemetry"
    version: str | None = None
    sink: TelemetrySink = field(default=_stdout_sink)
    # plugin protocol fields:
    schema: None = None
    endpoints: None = None
    middlewares: None = None
    hooks: None = None
    on_request: None = None
    on_response: None = None
    rate_limit: None = None
    error_codes: None = None

    async def init(self, ctx) -> None:  # type: ignore[no-untyped-def]
        # Explicit opt-out: advanced.telemetry=False suppresses emission even
        # though the plugin is present (useful for tests that opt-out without
        # rewiring the plugin list).
        if ctx.options.advanced.get("telemetry") is False:
            return None

        from better_auth import __version__

        plugin_ids = [p.id for p in ctx.plugins if p.id != "telemetry"]
        # `ctx.adapter` is the schema-driven transform wrapper; report the
        # underlying adapter's kind, not the wrapper's.
        underlying = getattr(ctx.adapter, "_raw", ctx.adapter)
        adapter_kind = type(underlying).__name__
        await self.sink({
            "kind": "startup",
            "version": __version__,
            "plugins": plugin_ids,
            "adapter": adapter_kind,
            "ts": int(time.time()),
        })
        return None


def telemetry(*, sink: TelemetrySink | None = None):
    """Construct the telemetry plugin. Off by default; opt in by adding to plugins."""
    return _TelemetryPlugin(sink=sink or _stdout_sink)


__all__ = ["telemetry"]
