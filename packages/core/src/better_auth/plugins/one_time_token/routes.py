"""One-time-token endpoint handlers.

Mirrors `reference/packages/better-auth/src/plugins/one-time-token/index.ts`.

The plugin issues a short-lived disposable token bound to a (user_id, purpose)
pair, persisted in the `verification` table with identifier `one-time-token:<token>`.
A subsequent `/verify-one-time-token` call consumes the row and returns the bound
user id + purpose.
"""

from __future__ import annotations

import secrets
import time

from pydantic import BaseModel

from better_auth.api.endpoint import create_auth_endpoint
from better_auth.error import APIError
from better_auth.types.adapter import Where
from better_auth.types.context import EndpointContext
from better_auth.types.endpoint import AuthEndpoint, EndpointOptions


_DEFAULT_EXPIRES_IN = 3 * 60  # 3 minutes — matches the reference default


class GenerateOneTimeTokenBody(BaseModel):
    purpose: str = "default"
    expires_in: int | None = None


class VerifyOneTimeTokenBody(BaseModel):
    token: str


def _now() -> int:
    return int(time.time())


async def _generate(ctx: EndpointContext) -> dict[str, object]:
    if ctx.session is None:
        raise APIError(401, "UNAUTHORIZED")
    body: GenerateOneTimeTokenBody = ctx.body
    token = secrets.token_urlsafe(32)
    expires_in = body.expires_in or _DEFAULT_EXPIRES_IN
    await ctx.auth.adapter.create(
        model="verification",
        data={
            "identifier": f"one-time-token:{token}",
            "value": f"{ctx.session.user_id}:{body.purpose}",
            "expiresAt": _now() + expires_in,
            "createdAt": _now(),
            "updatedAt": _now(),
        },
    )
    return {"token": token, "expiresIn": expires_in}


async def _verify(ctx: EndpointContext) -> dict[str, object]:
    body: VerifyOneTimeTokenBody = ctx.body
    identifier = f"one-time-token:{body.token}"
    where = (Where(field="identifier", value=identifier),)
    consume_one = getattr(ctx.auth.adapter, "consume_one", None)
    if consume_one is None:
        record = await ctx.auth.adapter.find_one(model="verification", where=where)
        if record:
            await ctx.auth.adapter.delete(model="verification", where=where)
    else:
        record = await consume_one(model="verification", where=where)
    if not record:
        raise APIError(400, "ONE_TIME_TOKEN_INVALID", message="Token is invalid")
    if int(record.get("expiresAt", 0)) < _now():
        raise APIError(400, "ONE_TIME_TOKEN_EXPIRED", message="Token has expired")
    value = str(record["value"])
    if ":" not in value:
        raise APIError(400, "ONE_TIME_TOKEN_INVALID", message="Token payload malformed")
    user_id, _, purpose = value.partition(":")
    return {"userId": user_id, "purpose": purpose}


GENERATE = create_auth_endpoint(
    "/generate-one-time-token",
    EndpointOptions(method="POST", body=GenerateOneTimeTokenBody, requires_session=True),
    _generate,
)

VERIFY = create_auth_endpoint(
    "/verify-one-time-token",
    EndpointOptions(method="POST", body=VerifyOneTimeTokenBody),
    _verify,
)


ALL: tuple[AuthEndpoint, ...] = (GENERATE, VERIFY)
