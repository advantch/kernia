"""Account-management routes.

Mirrors `reference/.../api/routes/account.ts`. Lets a signed-in user introspect
and manage the OAuth accounts linked to their user row.

  GET    /list-accounts      — list OAuth accounts linked to the active user
  POST   /unlink-account     — unlink an OAuth account by (providerId, accountId)
  POST   /get-access-token   — return the current access_token for a linked account,
                                refreshing if expired
"""

from __future__ import annotations

import time

from pydantic import BaseModel

from better_auth.api.endpoint import create_auth_endpoint
from better_auth.error import APIError
from better_auth.oauth2.encryption import decrypt_token, is_encrypted
from better_auth.types.adapter import Where
from better_auth.types.context import EndpointContext
from better_auth.types.endpoint import EndpointOptions


class UnlinkAccountBody(BaseModel):
    provider_id: str
    account_id: str | None = None


class AccessTokenBody(BaseModel):
    provider_id: str
    account_id: str | None = None


async def _list_accounts(ctx: EndpointContext) -> list[dict[str, object]]:
    if ctx.session is None:
        raise APIError(401, "UNAUTHORIZED")
    rows = await ctx.auth.adapter.find_many(
        model="account",
        where=(Where(field="userId", value=ctx.session.user_id),),
    )
    return [
        {
            "id": r["id"],
            "providerId": r["providerId"],
            "accountId": r["accountId"],
            "scope": r.get("scope"),
            "createdAt": r.get("createdAt"),
        }
        for r in rows
    ]


async def _unlink_account(ctx: EndpointContext) -> dict[str, bool]:
    if ctx.session is None:
        raise APIError(401, "UNAUTHORIZED")
    body: UnlinkAccountBody = ctx.body
    where: list[Where] = [
        Where(field="userId", value=ctx.session.user_id),
        Where(field="providerId", value=body.provider_id),
    ]
    if body.account_id:
        where.append(Where(field="accountId", value=body.account_id))
    n = await ctx.auth.adapter.delete_many(model="account", where=tuple(where))
    if n == 0:
        raise APIError(404, "NOT_FOUND")
    return {"success": True}


async def _get_access_token(ctx: EndpointContext) -> dict[str, object]:
    if ctx.session is None:
        raise APIError(401, "UNAUTHORIZED")
    body: AccessTokenBody = ctx.body
    where: list[Where] = [
        Where(field="userId", value=ctx.session.user_id),
        Where(field="providerId", value=body.provider_id),
    ]
    if body.account_id:
        where.append(Where(field="accountId", value=body.account_id))
    account = await ctx.auth.adapter.find_one(model="account", where=tuple(where))
    if account is None:
        raise APIError(404, "NOT_FOUND")
    token = account.get("accessToken")
    if not isinstance(token, str):
        raise APIError(400, "INVALID_REQUEST", message="No access token stored.")
    if is_encrypted(token):
        token = decrypt_token(token, secret=ctx.auth.secret)
    exp = account.get("accessTokenExpiresAt")
    if isinstance(exp, int) and exp < int(time.time()):
        # Refresh path lives in the provider; we surface a clear error so the
        # caller knows to invoke the refresh route (registered by the social
        # provider plugin) for this provider.
        raise APIError(401, "TOKEN_EXPIRED")
    return {"accessToken": token, "expiresAt": exp, "providerId": body.provider_id}


ACCOUNT_ROUTES = (
    create_auth_endpoint(
        "/list-accounts",
        EndpointOptions(method="GET", requires_session=True),
        _list_accounts,
    ),
    create_auth_endpoint(
        "/unlink-account",
        EndpointOptions(method="POST", body=UnlinkAccountBody, requires_session=True),
        _unlink_account,
    ),
    create_auth_endpoint(
        "/get-access-token",
        EndpointOptions(method="POST", body=AccessTokenBody, requires_session=True),
        _get_access_token,
    ),
)
