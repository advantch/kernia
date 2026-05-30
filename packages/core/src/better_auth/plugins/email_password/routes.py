"""Email/password endpoint definitions + handlers.

Mirrors the route handlers in
`reference/packages/better-auth/src/api/routes/sign-{up,in}-email.ts`.
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass

from better_auth.api.endpoint import create_auth_endpoint
from better_auth.context import (
    create_session,
    refresh_session_cookies,
    revoke_session,
    should_refresh_session,
)
from better_auth.crypto import hash_password, verify_password
from better_auth.error import APIError
from better_auth.types.adapter import Where
from better_auth.types.context import EndpointContext
from better_auth.types.endpoint import AuthEndpoint, EndpointOptions

# ----- request body shapes -----


@dataclass(frozen=True, slots=True)
class SignUpEmailBody:
    email: str
    password: str
    name: str | None = None


@dataclass(frozen=True, slots=True)
class SignInEmailBody:
    email: str
    password: str
    remember_me: bool = True


@dataclass(frozen=True, slots=True)
class ForgetPasswordBody:
    email: str
    redirect_to: str | None = None


@dataclass(frozen=True, slots=True)
class ResetPasswordBody:
    token: str
    password: str


# ----- handlers -----


def _validate_password(password: str, ctx: EndpointContext) -> None:
    opts = ctx.auth.options.email_and_password
    if len(password) < opts.min_password_length:
        raise APIError(400, "PASSWORD_TOO_SHORT")
    if len(password) > opts.max_password_length:
        raise APIError(400, "PASSWORD_TOO_LONG")


async def _sign_up_email(ctx: EndpointContext) -> dict[str, object]:
    body: SignUpEmailBody = ctx.body
    _validate_password(body.password, ctx)
    existing = await ctx.auth.adapter.find_one(
        model="user",
        where=(Where(field="email", value=body.email),),
    )
    if existing is not None:
        raise APIError(409, "EMAIL_ALREADY_IN_USE")

    now = int(time.time())
    # Route writes through with_hooks so plugin database_hooks (e.g. Stripe's
    # createCustomerOnSignUp) fire before/after user creation, matching
    # upstream's createWithHooks path. Falls back to the raw adapter only if the
    # hook runtime was not wired (it always is via init()).
    wh = ctx.auth.with_hooks
    user_data = {
        "email": body.email,
        "name": body.name,
        "emailVerified": False,
        "createdAt": now,
        "updatedAt": now,
    }
    if wh is not None:
        user = await wh.create("user", user_data)
    else:
        user = await ctx.auth.adapter.create(model="user", data=user_data)
    if user is None:
        # A before-hook aborted the write (returned False).
        raise APIError(400, "FAILED_TO_CREATE_USER")
    account_data = {
        "userId": user["id"],
        "accountId": user["id"],
        "providerId": "credential",
        "password": hash_password(body.password),
        "createdAt": now,
        "updatedAt": now,
    }
    if wh is not None:
        await wh.create("account", account_data)
    else:
        await ctx.auth.adapter.create(model="account", data=account_data)

    if ctx.auth.options.email_and_password.auto_sign_in:
        session, cookies = await create_session(
            ctx.auth,
            user_id=user["id"],
            ip_address=ctx.request.headers.get("x-forwarded-for"),
            user_agent=ctx.request.headers.get("user-agent"),
        )
        ctx.set_cookies.extend(cookies)
        return {"user": user, "session": {"id": session.id, "expiresAt": session.expires_at}}

    return {"user": user}


async def _sign_in_email(ctx: EndpointContext) -> dict[str, object]:
    body: SignInEmailBody = ctx.body
    user = await ctx.auth.adapter.find_one(
        model="user",
        where=(Where(field="email", value=body.email),),
    )
    if not user:
        raise APIError(401, "INVALID_CREDENTIALS")

    account = await ctx.auth.adapter.find_one(
        model="account",
        where=(
            Where(field="userId", value=user["id"]),
            Where(field="providerId", value="credential"),
        ),
    )
    if not account or not account.get("password"):
        raise APIError(401, "INVALID_CREDENTIALS")
    if not verify_password(body.password, account["password"]):
        raise APIError(401, "INVALID_CREDENTIALS")

    if ctx.auth.options.email_and_password.require_email_verification and not user.get("emailVerified"):
        raise APIError(403, "EMAIL_NOT_VERIFIED")

    session, cookies = await create_session(
        ctx.auth,
        user_id=user["id"],
        ip_address=ctx.request.headers.get("x-forwarded-for"),
        user_agent=ctx.request.headers.get("user-agent"),
        remember_me=body.remember_me,
    )
    ctx.set_cookies.extend(cookies)
    return {
        "user": {"id": user["id"], "email": user["email"], "name": user.get("name")},
        "session": {"id": session.id, "expiresAt": session.expires_at},
    }


async def _sign_out(ctx: EndpointContext) -> dict[str, object]:
    if ctx.session is None:
        raise APIError(401, "UNAUTHORIZED")
    cookies = await revoke_session(ctx.auth, token=ctx.session.token)
    ctx.set_cookies.extend(cookies)
    return {"success": True}


def _is_truthy_query(value: object) -> bool:
    if isinstance(value, list):
        value = value[0] if value else None
    return str(value).lower() in ("1", "true", "yes") if value is not None else False


async def _get_session(ctx: EndpointContext) -> dict[str, object] | None:
    if ctx.session is None:
        return None
    user = await ctx.auth.adapter.find_one(
        model="user",
        where=(Where(field="id", value=ctx.session.user_id),),
    )

    # Cookie refresh: re-issue `session_token` (and the `session_data` cache when
    # enabled) when the session is older than `update_age`, unless the caller
    # opted out with `?disableRefresh=true`. Each cookie is its own Set-Cookie
    # entry, preserving the distinct Max-Age of token vs. data cookies.
    disable_refresh = _is_truthy_query(ctx.request.query.get("disableRefresh"))
    if not disable_refresh and should_refresh_session(ctx.auth, ctx.session):
        ctx.set_cookies.extend(
            refresh_session_cookies(ctx.auth, session=ctx.session, user=user)
        )

    return {
        "session": {"id": ctx.session.id, "expiresAt": ctx.session.expires_at},
        "user": user,
    }


async def _forget_password(ctx: EndpointContext) -> dict[str, object]:
    body: ForgetPasswordBody = ctx.body
    user = await ctx.auth.adapter.find_one(
        model="user",
        where=(Where(field="email", value=body.email),),
    )
    # Always succeed (don't leak which emails are registered).
    if user:
        token = secrets.token_urlsafe(32)
        await ctx.auth.adapter.create(
            model="verification",
            data={
                "identifier": f"reset:{user['id']}",
                "value": token,
                "expiresAt": int(time.time()) + 3600,
            },
        )
        # Real impl would dispatch email; for MVP we return the token in dev mode.
        if ctx.auth.options.advanced.get("expose_reset_token_for_tests"):
            return {"success": True, "_token": token}
    return {"success": True}


async def _reset_password(ctx: EndpointContext) -> dict[str, object]:
    body: ResetPasswordBody = ctx.body
    _validate_password(body.password, ctx)
    consume_one = getattr(ctx.auth.adapter, "consume_one", None)
    where = (Where(field="value", value=body.token),)
    if consume_one is None:
        record = await ctx.auth.adapter.find_one(model="verification", where=where)
        if record:
            await ctx.auth.adapter.delete(model="verification", where=where)
    else:
        record = await consume_one(model="verification", where=where)
    if not record:
        raise APIError(400, "INVALID_REQUEST", message="Token is invalid or expired")
    if int(record.get("expiresAt", 0)) < int(time.time()):
        raise APIError(400, "INVALID_REQUEST", message="Token is expired")

    identifier = record["identifier"]
    if not identifier.startswith("reset:"):
        raise APIError(400, "INVALID_REQUEST")
    user_id = identifier.split(":", 1)[1]
    await ctx.auth.adapter.update(
        model="account",
        where=(
            Where(field="userId", value=user_id),
            Where(field="providerId", value="credential"),
        ),
        update={"password": hash_password(body.password)},
    )
    return {"success": True}


# ----- endpoint table -----

SIGN_UP_EMAIL = create_auth_endpoint(
    "/sign-up/email",
    EndpointOptions(method="POST", body=SignUpEmailBody),
    _sign_up_email,
)

SIGN_IN_EMAIL = create_auth_endpoint(
    "/sign-in/email",
    EndpointOptions(method="POST", body=SignInEmailBody),
    _sign_in_email,
)

SIGN_OUT = create_auth_endpoint(
    "/sign-out",
    EndpointOptions(method="POST", requires_session=False),
    _sign_out,
)

GET_SESSION = create_auth_endpoint(
    "/get-session",
    EndpointOptions(method="GET"),
    _get_session,
)

FORGET_PASSWORD = create_auth_endpoint(
    "/forget-password",
    EndpointOptions(method="POST", body=ForgetPasswordBody),
    _forget_password,
)

RESET_PASSWORD = create_auth_endpoint(
    "/reset-password",
    EndpointOptions(method="POST", body=ResetPasswordBody),
    _reset_password,
)


ALL: tuple[AuthEndpoint, ...] = (
    SIGN_UP_EMAIL,
    SIGN_IN_EMAIL,
    SIGN_OUT,
    GET_SESSION,
    FORGET_PASSWORD,
    RESET_PASSWORD,
)
