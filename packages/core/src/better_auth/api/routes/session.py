"""Session-management routes.

Mirrors `reference/.../api/routes/session.ts`:
  GET    /list-sessions         — list all sessions of the active user
  POST   /revoke-session        — revoke a single session by id
  POST   /revoke-sessions       — revoke every session of the active user
  POST   /revoke-other-sessions — revoke every session EXCEPT the current one
  POST   /update-session        — refresh updatedAt; optional metadata update
"""

from __future__ import annotations

import time

from pydantic import BaseModel

from better_auth.api.endpoint import create_auth_endpoint
from better_auth.error import APIError
from better_auth.types.adapter import Where
from better_auth.types.context import EndpointContext
from better_auth.types.endpoint import EndpointOptions


class RevokeSessionBody(BaseModel):
    session_id: str


class UpdateSessionBody(BaseModel):
    ip_address: str | None = None
    user_agent: str | None = None


async def _list_sessions(ctx: EndpointContext) -> list[dict[str, object]]:
    if ctx.session is None:
        raise APIError(401, "UNAUTHORIZED")
    rows = await ctx.auth.adapter.find_many(
        model="session",
        where=(Where(field="userId", value=ctx.session.user_id),),
        sort_by=None,
    )
    return [
        {
            "id": r["id"],
            "expiresAt": r["expiresAt"],
            "ipAddress": r.get("ipAddress"),
            "userAgent": r.get("userAgent"),
            "current": r["token"] == ctx.session.token,
        }
        for r in rows
    ]


async def _revoke_session(ctx: EndpointContext) -> dict[str, bool]:
    if ctx.session is None:
        raise APIError(401, "UNAUTHORIZED")
    body: RevokeSessionBody = ctx.body
    # only allow revoking your own sessions
    target = await ctx.auth.adapter.find_one(
        model="session",
        where=(
            Where(field="id", value=body.session_id),
            Where(field="userId", value=ctx.session.user_id),
        ),
    )
    if target is None:
        raise APIError(404, "NOT_FOUND")
    await ctx.auth.adapter.delete_many(
        model="session",
        where=(Where(field="id", value=body.session_id),),
    )
    return {"success": True}


async def _revoke_sessions(ctx: EndpointContext) -> dict[str, int]:
    if ctx.session is None:
        raise APIError(401, "UNAUTHORIZED")
    n = await ctx.auth.adapter.delete_many(
        model="session",
        where=(Where(field="userId", value=ctx.session.user_id),),
    )
    return {"revoked": n}


async def _revoke_other_sessions(ctx: EndpointContext) -> dict[str, int]:
    if ctx.session is None:
        raise APIError(401, "UNAUTHORIZED")
    n = await ctx.auth.adapter.delete_many(
        model="session",
        where=(
            Where(field="userId", value=ctx.session.user_id),
            Where(field="token", value=ctx.session.token, operator="ne"),
        ),
    )
    return {"revoked": n}


async def _update_session(ctx: EndpointContext) -> dict[str, object]:
    if ctx.session is None:
        raise APIError(401, "UNAUTHORIZED")
    body: UpdateSessionBody = ctx.body
    update: dict[str, object] = {"updatedAt": int(time.time())}
    if body.ip_address is not None:
        update["ipAddress"] = body.ip_address
    if body.user_agent is not None:
        update["userAgent"] = body.user_agent
    row = await ctx.auth.adapter.update(
        model="session",
        where=(Where(field="id", value=ctx.session.id),),
        update=update,
    )
    return {"session": row}


SESSION_ROUTES = (
    create_auth_endpoint(
        "/list-sessions", EndpointOptions(method="GET", requires_session=True), _list_sessions
    ),
    create_auth_endpoint(
        "/revoke-session",
        EndpointOptions(method="POST", body=RevokeSessionBody, requires_session=True),
        _revoke_session,
    ),
    create_auth_endpoint(
        "/revoke-sessions",
        EndpointOptions(method="POST", requires_session=True),
        _revoke_sessions,
    ),
    create_auth_endpoint(
        "/revoke-other-sessions",
        EndpointOptions(method="POST", requires_session=True),
        _revoke_other_sessions,
    ),
    create_auth_endpoint(
        "/update-session",
        EndpointOptions(method="POST", body=UpdateSessionBody, requires_session=True),
        _update_session,
    ),
)
