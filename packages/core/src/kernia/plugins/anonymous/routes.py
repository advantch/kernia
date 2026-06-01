"""Anonymous plugin endpoint handler.

Mirrors `reference/packages/better-auth/src/plugins/anonymous/index.ts`.
"""

from __future__ import annotations

import inspect
import re
import secrets
import time
from dataclasses import dataclass
from typing import Any

from kernia.api.endpoint import create_auth_endpoint
from kernia.context import create_session
from kernia.error import APIError
from kernia.types.adapter import Where
from kernia.types.context import EndpointContext
from kernia.types.endpoint import AuthEndpoint, EndpointOptions

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_OPTIONS_KEY = "anonymous"


def _opts(ctx: EndpointContext) -> dict[str, object]:
    return dict(ctx.auth.plugin_state.get(_OPTIONS_KEY) or {})


async def _maybe_await(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value


@dataclass(frozen=True, slots=True)
class SignInAnonymousBody:
    name: str | None = None


async def _generate_email(ctx: EndpointContext, opts: dict[str, object]) -> str:
    """Mirror upstream `getAnonUserEmail`."""
    gen = opts.get("generate_random_email")
    if gen is not None:
        custom = await _maybe_await(gen())  # type: ignore[operator]
        if custom:
            if not _EMAIL_RE.match(str(custom)):
                raise APIError(400, "INVALID_EMAIL_FORMAT")
            return str(custom)
    anon_id = secrets.token_urlsafe(12)
    domain = opts.get("email_domain_name")
    if domain:
        return f"temp-{anon_id}@{domain}"
    return f"temp-{anon_id}@anonymous.local"


async def _sign_in_anonymous(ctx: EndpointContext) -> dict[str, object]:
    opts = _opts(ctx)
    # Reject if the caller already has an anonymous session.
    if ctx.session is not None:
        existing_user = await ctx.auth.adapter.find_one(
            model="user",
            where=(Where(field="id", value=ctx.session.user_id),),
        )
        if existing_user and existing_user.get("isAnonymous"):
            raise APIError(
                400,
                "ANONYMOUS_USERS_CANNOT_SIGN_IN_AGAIN_ANONYMOUSLY",
            )

    body: SignInAnonymousBody | None = ctx.body if ctx.body else None
    name = (body.name if body else None) or "Anonymous"
    gen_name = opts.get("generate_name")
    if gen_name is not None:
        generated = await _maybe_await(gen_name(ctx))  # type: ignore[operator]
        if generated:
            name = str(generated)
    email = await _generate_email(ctx, opts)
    now = int(time.time())

    user = await ctx.auth.adapter.create(
        model="user",
        data={
            "email": email,
            "name": name,
            "emailVerified": False,
            "isAnonymous": True,
            "createdAt": now,
            "updatedAt": now,
        },
    )
    session, cookies = await create_session(
        ctx.auth,
        user_id=user["id"],
        ip_address=ctx.request.headers.get("x-forwarded-for"),
        user_agent=ctx.request.headers.get("user-agent"),
    )
    ctx.set_cookies.extend(cookies)
    return {
        "token": session.token,
        "user": user,
        "session": {"id": session.id, "expiresAt": session.expires_at},
    }


async def _delete_anonymous_user(ctx: EndpointContext) -> dict[str, object]:
    opts = _opts(ctx)
    if bool(opts.get("disable_delete_anonymous_user", False)):
        raise APIError(400, "DELETE_ANONYMOUS_USER_DISABLED")
    if ctx.session is None:
        raise APIError(401, "USER_NOT_FOUND")
    user = await ctx.auth.adapter.find_one(
        model="user",
        where=(Where(field="id", value=ctx.session.user_id),),
    )
    if not user or not user.get("isAnonymous"):
        raise APIError(403, "USER_IS_NOT_ANONYMOUS")
    try:
        await ctx.auth.adapter.delete_many(
            model="session",
            where=(Where(field="userId", value=user["id"]),),
        )
    except Exception:
        raise APIError(500, "FAILED_TO_DELETE_ANONYMOUS_USER_SESSIONS") from None
    try:
        await ctx.auth.adapter.delete(
            model="user",
            where=(Where(field="id", value=user["id"]),),
        )
    except Exception:
        raise APIError(500, "FAILED_TO_DELETE_ANONYMOUS_USER") from None
    return {"success": True}


SIGN_IN_ANONYMOUS = create_auth_endpoint(
    "/sign-in/anonymous",
    EndpointOptions(method="POST", body=SignInAnonymousBody),
    _sign_in_anonymous,
)

DELETE_ANONYMOUS_USER = create_auth_endpoint(
    "/delete-anonymous-user",
    EndpointOptions(method="POST"),
    _delete_anonymous_user,
)


ALL: tuple[AuthEndpoint, ...] = (SIGN_IN_ANONYMOUS, DELETE_ANONYMOUS_USER)
