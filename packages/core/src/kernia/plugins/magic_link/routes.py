"""Magic-link endpoint handlers.

Mirrors `reference/packages/better-auth/src/plugins/magic-link/index.ts`.

  * POST `/sign-in/magic-link` — generate a verification token, persist it in
    the core `verification` table, and dispatch the link via the plugin-provided
    `send_magic_link` callable.
  * GET  `/magic-link/verify`  — atomically consume the token, sign the user in
    (auto-creating an account when `disable_sign_up` is False), and return the
    callback URL the caller asked us to redirect to.

The router always serializes JSON; we therefore return `{redirect, session, user}`
rather than emitting a 302. Framework integrations may inspect `redirect` and turn
it into a real HTTP redirect.
"""

from __future__ import annotations

import json
import secrets
import time
from urllib.parse import urlencode

from pydantic import BaseModel, Field

from kernia.api.endpoint import create_auth_endpoint
from kernia.context import create_session
from kernia.error import APIError
from kernia.types.adapter import Where
from kernia.types.context import EndpointContext
from kernia.types.endpoint import AuthEndpoint, EndpointOptions


class SignInMagicLinkBody(BaseModel):
    email: str
    callback_url: str = Field(default="/", alias="callbackURL")
    new_user_callback_url: str | None = Field(default=None, alias="newUserCallbackURL")
    name: str | None = None

    model_config = {"populate_by_name": True}


class MagicLinkVerifyQuery(BaseModel):
    token: str
    callback_url: str | None = Field(default=None, alias="callbackURL")
    new_user_callback_url: str | None = Field(default=None, alias="newUserCallbackURL")

    model_config = {"populate_by_name": True}


_OPTIONS_KEY = "magic-link"


def _opts(ctx: EndpointContext) -> dict[str, object]:
    return dict(ctx.auth.options.advanced.get(_OPTIONS_KEY) or {})


def _now() -> int:
    return int(time.time())


async def _sign_in_magic_link(ctx: EndpointContext) -> dict[str, object]:
    body: SignInMagicLinkBody = ctx.body
    opts = _opts(ctx)
    expires_in = int(opts.get("expires_in", 5 * 60))  # type: ignore[arg-type]
    send_magic_link = opts.get("send_magic_link")
    if send_magic_link is None:
        raise APIError(
            500,
            "MAGIC_LINK_NOT_CONFIGURED",
            message="send_magic_link callable is not configured",
        )

    token = secrets.token_urlsafe(32)
    payload = json.dumps({"email": body.email, "name": body.name})
    await ctx.auth.adapter.create(
        model="verification",
        data={
            "identifier": f"magic-link:{token}",
            "value": payload,
            "expiresAt": _now() + expires_in,
            "createdAt": _now(),
            "updatedAt": _now(),
        },
    )
    query = {"token": token, "callbackURL": body.callback_url}
    if body.new_user_callback_url:
        query["newUserCallbackURL"] = body.new_user_callback_url
    url = f"{ctx.auth.base_url}/magic-link/verify?{urlencode(query)}"
    await send_magic_link(body.email, url, token)  # type: ignore[misc]
    return {"success": True, "status": True}


async def _verify(ctx: EndpointContext) -> dict[str, object]:
    raw_query = ctx.request.query
    try:
        query = MagicLinkVerifyQuery.model_validate({
            k: (v[0] if isinstance(v, list) else v) for k, v in raw_query.items()
        })
    except Exception as e:  # noqa: BLE001
        raise APIError(400, "INVALID_REQUEST", message=str(e)) from None

    opts = _opts(ctx)
    disable_sign_up = bool(opts.get("disable_sign_up", False))
    identifier = f"magic-link:{query.token}"
    where = (Where(field="identifier", value=identifier),)

    consume_one = getattr(ctx.auth.adapter, "consume_one", None)
    if consume_one is None:
        record = await ctx.auth.adapter.find_one(model="verification", where=where)
        if record:
            await ctx.auth.adapter.delete(model="verification", where=where)
    else:
        record = await consume_one(model="verification", where=where)

    if not record:
        raise APIError(400, "MAGIC_LINK_INVALID", message="Magic link is invalid")
    if int(record.get("expiresAt", 0)) < _now():
        raise APIError(400, "MAGIC_LINK_EXPIRED", message="Magic link has expired")

    data = json.loads(record["value"])
    email = data["email"]
    name = data.get("name")
    user = await ctx.auth.adapter.find_one(
        model="user",
        where=(Where(field="email", value=email),),
    )

    is_new_user = False
    if user is None:
        if disable_sign_up:
            raise APIError(
                403,
                "MAGIC_LINK_SIGN_UP_DISABLED",
                message="Sign-up via magic link is disabled",
            )
        now = _now()
        user = await ctx.auth.adapter.create(
            model="user",
            data={
                "email": email,
                "name": name,
                "emailVerified": True,
                "createdAt": now,
                "updatedAt": now,
            },
        )
        is_new_user = True
    elif not user.get("emailVerified"):
        await ctx.auth.adapter.update(
            model="user",
            where=(Where(field="id", value=user["id"]),),
            update={"emailVerified": True, "updatedAt": _now()},
        )

    session, cookies = await create_session(
        ctx.auth,
        user_id=user["id"],
        ip_address=ctx.request.headers.get("x-forwarded-for"),
        user_agent=ctx.request.headers.get("user-agent"),
    )
    ctx.set_cookies.extend(cookies)

    redirect = query.callback_url or "/"
    if is_new_user and query.new_user_callback_url:
        redirect = query.new_user_callback_url

    ctx.response_headers["Location"] = redirect
    return {
        "redirect": redirect,
        "user": user,
        "session": {"id": session.id, "expiresAt": session.expires_at},
        "isNewUser": is_new_user,
    }


SIGN_IN_MAGIC_LINK = create_auth_endpoint(
    "/sign-in/magic-link",
    EndpointOptions(method="POST", body=SignInMagicLinkBody),
    _sign_in_magic_link,
)

MAGIC_LINK_VERIFY = create_auth_endpoint(
    "/magic-link/verify",
    EndpointOptions(method="GET"),
    _verify,
)


ALL: tuple[AuthEndpoint, ...] = (SIGN_IN_MAGIC_LINK, MAGIC_LINK_VERIFY)
