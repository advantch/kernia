"""Email-verification routes.

Mirrors `reference/.../api/routes/email-verification.ts`:
  POST   /send-verification-email
  POST   /verify-email                (also accepts GET with ?token=... for email-link UX)

The plugin emits an email via a user-supplied `send_verification_email` callable
configured on `KerniaOptions.advanced["send_verification_email"]`. If absent,
the route still produces a token but logs a warning; tests can use a `MockSMTP`
to capture and inspect.
"""

from __future__ import annotations

import secrets
import time
from collections.abc import Awaitable, Callable

from pydantic import BaseModel

from kernia.api.endpoint import create_auth_endpoint
from kernia.error import APIError
from kernia.types.adapter import Where
from kernia.types.context import EndpointContext
from kernia.types.endpoint import EndpointOptions


class SendVerificationBody(BaseModel):
    email: str | None = None
    callback_url: str | None = None


class VerifyEmailBody(BaseModel):
    token: str


_VERIFY_TTL = 60 * 60 * 24  # 24h


async def _send_verification_email(ctx: EndpointContext) -> dict[str, object]:
    body: SendVerificationBody = ctx.body
    target_email = body.email
    if target_email is None and ctx.session is not None:
        # use the active user's email
        user = await ctx.auth.adapter.find_one(
            model="user", where=(Where(field="id", value=ctx.session.user_id),)
        )
        if user is None:
            raise APIError(404, "USER_NOT_FOUND")
        target_email = user["email"]
    if not target_email:
        raise APIError(400, "INVALID_REQUEST", message="Email is required.")
    token = secrets.token_urlsafe(32)
    await ctx.auth.adapter.create(
        model="verification",
        data={
            "identifier": f"verify-email:{target_email}",
            "value": token,
            "expiresAt": int(time.time()) + _VERIFY_TTL,
        },
    )
    sender: Callable[..., Awaitable[None]] | None = ctx.auth.options.advanced.get(
        "send_verification_email"
    )
    if sender is not None:
        await sender(
            email=target_email,
            token=token,
            callback_url=body.callback_url,
        )
    # dev/test path
    if ctx.auth.options.advanced.get("expose_verification_token_for_tests"):
        return {"success": True, "_token": token}
    return {"success": True}


async def _verify_email(ctx: EndpointContext) -> dict[str, object]:
    if ctx.body is not None:
        token = ctx.body.token
    else:
        token = ctx.request.query.get("token")
        if isinstance(token, list):
            token = token[0] if token else None
    if not isinstance(token, str) or not token:
        raise APIError(400, "INVALID_REQUEST")
    consume_one = getattr(ctx.auth.adapter, "consume_one", None)
    where = (Where(field="value", value=token),)
    if consume_one is None:
        record = await ctx.auth.adapter.find_one(model="verification", where=where)
        if record:
            await ctx.auth.adapter.delete(model="verification", where=where)
    else:
        record = await consume_one(model="verification", where=where)
    if not record:
        raise APIError(400, "INVALID_REQUEST", message="Token is invalid or already used.")
    if int(record.get("expiresAt", 0)) < int(time.time()):
        raise APIError(400, "INVALID_REQUEST", message="Token is expired.")
    identifier = record["identifier"]
    if not isinstance(identifier, str) or not identifier.startswith("verify-email:"):
        raise APIError(400, "INVALID_REQUEST")
    email = identifier.split(":", 1)[1]
    user = await ctx.auth.adapter.find_one(model="user", where=(Where(field="email", value=email),))
    if user is None:
        # pending email-change flow: identifier could match a `email-change:<userId>` row
        raise APIError(404, "USER_NOT_FOUND")
    updated = await ctx.auth.adapter.update(
        model="user",
        where=(Where(field="id", value=user["id"]),),
        update={"emailVerified": True, "updatedAt": int(time.time())},
    )
    return {"user": updated}


EMAIL_VERIFICATION_ROUTES = (
    create_auth_endpoint(
        "/send-verification-email",
        EndpointOptions(method="POST", body=SendVerificationBody),
        _send_verification_email,
    ),
    create_auth_endpoint(
        "/verify-email",
        EndpointOptions(method="POST", body=VerifyEmailBody),
        _verify_email,
    ),
    create_auth_endpoint(
        "/verify-email",
        EndpointOptions(method="GET"),
        _verify_email,
    ),
)
