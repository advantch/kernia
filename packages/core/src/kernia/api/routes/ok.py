"""`/ok` health check. Mirrors `reference/.../api/routes/ok.ts`."""

from __future__ import annotations

from kernia.api.endpoint import create_auth_endpoint
from kernia.types.context import EndpointContext
from kernia.types.endpoint import EndpointOptions


async def _ok(ctx: EndpointContext) -> dict[str, bool]:
    return {"ok": True}


OK = create_auth_endpoint("/ok", EndpointOptions(method="GET"), _ok)
OK_ROUTES = (OK,)
