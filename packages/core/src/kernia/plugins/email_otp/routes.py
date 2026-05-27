"""Email-OTP endpoint handlers.

Mirrors `reference/packages/better-auth/src/plugins/email-otp/routes.ts`.

Purposes use the `email-otp:<purpose>:<email>` identifier on the verification
table. Purposes:

  * `sign-in`         — sign in (auto-creates a user)
  * `email-verification` — verify the email of an existing user
  * `forget-password` — reset password
  * `change-email`    — request a new email and confirm with OTP

All OTPs are numeric of length `otp_length` (default 6).
"""

from __future__ import annotations

import secrets
import time

from pydantic import BaseModel

from kernia.api.endpoint import create_auth_endpoint
from kernia.context import create_session
from kernia.crypto import hash_password
from kernia.error import APIError
from kernia.types.adapter import Where
from kernia.types.context import EndpointContext
from kernia.types.endpoint import AuthEndpoint, EndpointOptions


_OPTIONS_KEY = "email-otp"
_DEFAULT_LENGTH = 6
_DEFAULT_EXPIRES_IN = 5 * 60  # 5 minutes


def _opts(ctx: EndpointContext) -> dict[str, object]:
    return dict(ctx.auth.options.advanced.get(_OPTIONS_KEY) or {})


def _otp_length(ctx: EndpointContext) -> int:
    return int(_opts(ctx).get("otp_length", _DEFAULT_LENGTH))  # type: ignore[arg-type]


def _expires_in(ctx: EndpointContext) -> int:
    return int(_opts(ctx).get("expires_in", _DEFAULT_EXPIRES_IN))  # type: ignore[arg-type]


def generate_otp(length: int = _DEFAULT_LENGTH) -> str:
    """Generate a numeric OTP. Module-level so unit tests can hit it directly."""
    if length <= 0:
        raise ValueError("OTP length must be positive")
    upper = 10**length
    return f"{secrets.randbelow(upper):0{length}d}"


def _identifier(purpose: str, email: str) -> str:
    return f"email-otp:{purpose}:{email.lower()}"


def _now() -> int:
    return int(time.time())


async def _send_otp(ctx: EndpointContext, email: str, otp: str, purpose: str) -> None:
    fn = _opts(ctx).get("send_otp")
    if fn is None:
        raise APIError(
            500,
            "EMAIL_OTP_NOT_CONFIGURED",
            message="send_otp callable is not configured",
        )
    await fn(email, otp, purpose)  # type: ignore[misc]


async def _create_otp(
    ctx: EndpointContext, *, email: str, purpose: str
) -> str:
    otp = generate_otp(_otp_length(ctx))
    identifier = _identifier(purpose, email)
    # Replace any prior pending OTP for the same (purpose, email).
    await ctx.auth.adapter.delete_many(
        model="verification",
        where=(Where(field="identifier", value=identifier),),
    )
    now = _now()
    await ctx.auth.adapter.create(
        model="verification",
        data={
            "identifier": identifier,
            "value": f"{otp}:0",
            "expiresAt": now + _expires_in(ctx),
            "createdAt": now,
            "updatedAt": now,
        },
    )
    return otp


async def _consume_otp(
    ctx: EndpointContext,
    *,
    email: str,
    purpose: str,
    otp: str,
) -> None:
    identifier = _identifier(purpose, email)
    record = await ctx.auth.adapter.find_one(
        model="verification",
        where=(Where(field="identifier", value=identifier),),
    )
    if not record:
        raise APIError(400, "INVALID_OTP", message="OTP is invalid")
    if int(record.get("expiresAt", 0)) < _now():
        await ctx.auth.adapter.delete_many(
            model="verification",
            where=(Where(field="identifier", value=identifier),),
        )
        raise APIError(400, "OTP_EXPIRED", message="OTP has expired")
    stored, _, attempts_str = str(record["value"]).rpartition(":")
    attempts = int(attempts_str or "0")
    if attempts >= 3:
        await ctx.auth.adapter.delete_many(
            model="verification",
            where=(Where(field="identifier", value=identifier),),
        )
        raise APIError(403, "TOO_MANY_ATTEMPTS", message="Too many invalid attempts")
    if stored != otp:
        await ctx.auth.adapter.update(
            model="verification",
            where=(Where(field="identifier", value=identifier),),
            update={"value": f"{stored}:{attempts + 1}", "updatedAt": _now()},
        )
        raise APIError(400, "INVALID_OTP", message="OTP is invalid")
    # Success — consume.
    await ctx.auth.adapter.delete_many(
        model="verification",
        where=(Where(field="identifier", value=identifier),),
    )


# ---------- request bodies -----------------------------------------------------


class EmailBody(BaseModel):
    email: str


class VerifyOTPBody(BaseModel):
    email: str
    otp: str


class ResetPasswordBody(BaseModel):
    email: str
    otp: str
    password: str


class RequestEmailChangeBody(BaseModel):
    new_email: str


class ChangeEmailBody(BaseModel):
    new_email: str
    otp: str


class SendVerificationOTPBody(BaseModel):
    email: str
    type: str = "email-verification"


# ---------- handlers -----------------------------------------------------------


async def _sign_in_send(ctx: EndpointContext) -> dict[str, object]:
    body: EmailBody = ctx.body
    opts = _opts(ctx)
    disable_sign_up = bool(opts.get("disable_sign_up", False))
    if disable_sign_up:
        user = await ctx.auth.adapter.find_one(
            model="user", where=(Where(field="email", value=body.email.lower()),)
        )
        if user is None:
            raise APIError(
                403,
                "EMAIL_OTP_SIGN_UP_DISABLED",
                message="Sign-up via email OTP is disabled",
            )
    otp = await _create_otp(ctx, email=body.email, purpose="sign-in")
    await _send_otp(ctx, body.email, otp, "sign-in")
    return {"success": True}


async def _sign_in_verify(ctx: EndpointContext) -> dict[str, object]:
    body: VerifyOTPBody = ctx.body
    await _consume_otp(ctx, email=body.email, purpose="sign-in", otp=body.otp)
    user = await ctx.auth.adapter.find_one(
        model="user", where=(Where(field="email", value=body.email.lower()),)
    )
    if user is None:
        now = _now()
        user = await ctx.auth.adapter.create(
            model="user",
            data={
                "email": body.email.lower(),
                "emailVerified": True,
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
        "user": user,
        "session": {"id": session.id, "expiresAt": session.expires_at},
    }


async def _send_verification_otp(ctx: EndpointContext) -> dict[str, object]:
    body: SendVerificationOTPBody = ctx.body
    otp = await _create_otp(ctx, email=body.email, purpose="email-verification")
    await _send_otp(ctx, body.email, otp, "email-verification")
    return {"success": True}


async def _verify_email(ctx: EndpointContext) -> dict[str, object]:
    if ctx.session is None:
        raise APIError(401, "UNAUTHORIZED")
    body: VerifyOTPBody = ctx.body
    user = await ctx.auth.adapter.find_one(
        model="user", where=(Where(field="id", value=ctx.session.user_id),)
    )
    if user is None or user.get("email", "").lower() != body.email.lower():
        raise APIError(400, "INVALID_OTP", message="OTP does not match this user")
    await _consume_otp(
        ctx, email=body.email, purpose="email-verification", otp=body.otp
    )
    await ctx.auth.adapter.update(
        model="user",
        where=(Where(field="id", value=user["id"]),),
        update={"emailVerified": True, "updatedAt": _now()},
    )
    return {"success": True}


async def _forget_password_send(ctx: EndpointContext) -> dict[str, object]:
    body: EmailBody = ctx.body
    user = await ctx.auth.adapter.find_one(
        model="user", where=(Where(field="email", value=body.email.lower()),)
    )
    if user is not None:
        otp = await _create_otp(ctx, email=body.email, purpose="forget-password")
        await _send_otp(ctx, body.email, otp, "forget-password")
    # Always say success — avoid leaking which addresses are registered.
    return {"success": True}


async def _reset_password(ctx: EndpointContext) -> dict[str, object]:
    body: ResetPasswordBody = ctx.body
    await _consume_otp(
        ctx, email=body.email, purpose="forget-password", otp=body.otp
    )
    user = await ctx.auth.adapter.find_one(
        model="user", where=(Where(field="email", value=body.email.lower()),)
    )
    if user is None:
        raise APIError(400, "INVALID_OTP")
    existing = await ctx.auth.adapter.find_one(
        model="account",
        where=(
            Where(field="userId", value=user["id"]),
            Where(field="providerId", value="credential"),
        ),
    )
    new_hash = hash_password(body.password)
    if existing:
        await ctx.auth.adapter.update(
            model="account",
            where=(Where(field="id", value=existing["id"]),),
            update={"password": new_hash, "updatedAt": _now()},
        )
    else:
        now = _now()
        await ctx.auth.adapter.create(
            model="account",
            data={
                "userId": user["id"],
                "accountId": user["id"],
                "providerId": "credential",
                "password": new_hash,
                "createdAt": now,
                "updatedAt": now,
            },
        )
    return {"success": True}


async def _request_email_change(ctx: EndpointContext) -> dict[str, object]:
    if ctx.session is None:
        raise APIError(401, "UNAUTHORIZED")
    body: RequestEmailChangeBody = ctx.body
    otp = await _create_otp(ctx, email=body.new_email, purpose="change-email")
    await _send_otp(ctx, body.new_email, otp, "change-email")
    return {"success": True}


async def _change_email(ctx: EndpointContext) -> dict[str, object]:
    if ctx.session is None:
        raise APIError(401, "UNAUTHORIZED")
    body: ChangeEmailBody = ctx.body
    await _consume_otp(
        ctx, email=body.new_email, purpose="change-email", otp=body.otp
    )
    await ctx.auth.adapter.update(
        model="user",
        where=(Where(field="id", value=ctx.session.user_id),),
        update={
            "email": body.new_email.lower(),
            "emailVerified": True,
            "updatedAt": _now(),
        },
    )
    return {"success": True}


# ---------- endpoint table -----------------------------------------------------


SIGN_IN_EMAIL_OTP = create_auth_endpoint(
    "/sign-in/email-otp",
    EndpointOptions(method="POST", body=EmailBody),
    _sign_in_send,
)

EMAIL_OTP_VERIFY = create_auth_endpoint(
    "/email-otp/verify",
    EndpointOptions(method="POST", body=VerifyOTPBody),
    _sign_in_verify,
)

SEND_VERIFICATION_OTP = create_auth_endpoint(
    "/email-otp/send-verification-otp",
    EndpointOptions(method="POST", body=SendVerificationOTPBody),
    _send_verification_otp,
)

VERIFY_EMAIL = create_auth_endpoint(
    "/email-otp/verify-email",
    EndpointOptions(method="POST", body=VerifyOTPBody, requires_session=True),
    _verify_email,
)

FORGET_PASSWORD_OTP = create_auth_endpoint(
    "/forget-password/email-otp",
    EndpointOptions(method="POST", body=EmailBody),
    _forget_password_send,
)

RESET_PASSWORD_OTP = create_auth_endpoint(
    "/email-otp/reset-password",
    EndpointOptions(method="POST", body=ResetPasswordBody),
    _reset_password,
)

REQUEST_EMAIL_CHANGE = create_auth_endpoint(
    "/email-otp/request-email-change",
    EndpointOptions(method="POST", body=RequestEmailChangeBody, requires_session=True),
    _request_email_change,
)

CHANGE_EMAIL = create_auth_endpoint(
    "/email-otp/change-email",
    EndpointOptions(method="POST", body=ChangeEmailBody, requires_session=True),
    _change_email,
)


ALL: tuple[AuthEndpoint, ...] = (
    SIGN_IN_EMAIL_OTP,
    EMAIL_OTP_VERIFY,
    SEND_VERIFICATION_OTP,
    VERIFY_EMAIL,
    FORGET_PASSWORD_OTP,
    RESET_PASSWORD_OTP,
    REQUEST_EMAIL_CHANGE,
    CHANGE_EMAIL,
)
