"""`/error` route. Mirrors `reference/.../api/routes/error.ts`.

Returns a structured error envelope from a query string `?error=CODE`. Used as a
landing page for failed OAuth redirects that can't include a JSON body.
"""

from __future__ import annotations

from kernia.api.endpoint import create_auth_endpoint
from kernia.error import APIError
from kernia.types.context import EndpointContext
from kernia.types.endpoint import EndpointOptions


async def _error(ctx: EndpointContext) -> dict[str, object]:
    code_q = ctx.request.query.get("error")
    if isinstance(code_q, list):
        code_q = code_q[0] if code_q else None
    code = code_q or "INTERNAL"
    raise APIError(400, code)


ERROR = create_auth_endpoint("/error", EndpointOptions(method="GET"), _error)
ERROR_ROUTES = (ERROR,)
