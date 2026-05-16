"""Anonymous, opt-in usage telemetry.

Mirrors `reference/packages/telemetry/`. Off by default. When opted in (via
`BetterAuthOptions.advanced["telemetry"] = True`), emits a single event at startup
with: better-auth-python version, registered plugin ids, adapter kind. No PII.

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
        from better_auth import __version__

        plugin_ids = [p.id for p in ctx.plugins if p.id != "telemetry"]
        adapter_kind = type(ctx.adapter).__name__
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
