"""`/ok` health check. Mirrors `reference/.../api/routes/ok.ts`."""

from __future__ import annotations

from better_auth.api.endpoint import create_auth_endpoint
from better_auth.types.context import EndpointContext
from better_auth.types.endpoint import EndpointOptions


async def _ok(ctx: EndpointContext) -> dict[str, bool]:
    return {"ok": True}


OK = create_auth_endpoint("/ok", EndpointOptions(method="GET"), _ok)
OK_ROUTES = (OK,)
