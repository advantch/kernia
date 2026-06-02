"""Phone-number endpoint handlers.

Mirrors `reference/packages/better-auth/src/plugins/phone-number/routes.ts`.

  * POST `/sign-in/phone-number`             — credential sign-in by phone.
  * POST `/phone-number/send-otp`            — dispatch an SMS OTP.
  * POST `/phone-number/verify`              — verify OTP; create or sign in.
  * POST `/phone-number/request-password-reset` — SMS OTP for password reset.
  * POST `/phone-number/reset-password`      — verify OTP + update password.

The user's phone number lives on the `user` row (`phoneNumber`,
`phoneNumberVerified`). Credentials reuse the same `account` row shape as
email/password (`providerId="credential"`), so phone-number sign-in can re-use
existing accounts.
"""

from __future__ import annotations

import secrets
import time

from pydantic import AliasChoices, BaseModel, Field

from kernia.api.endpoint import create_auth_endpoint
from kernia.context import create_session
from kernia.crypto import hash_password, verify_password
from kernia.error import APIError
from kernia.types.adapter import Where
from kernia.types.context import EndpointContext
from kernia.types.endpoint import AuthEndpoint, EndpointOptions

_OPTIONS_KEY = "phone-number"
_DEFAULT_LENGTH = 6
_DEFAULT_EXPIRES_IN = 5 * 60


def _opts(ctx: EndpointContext) -> dict[str, object]:
    return dict(ctx.auth.options.advanced.get(_OPTIONS_KEY) or {})


def _otp_length(ctx: EndpointContext) -> int:
    return int(_opts(ctx).get("otp_length", _DEFAULT_LENGTH))  # type: ignore[arg-type]


def _expires_in(ctx: EndpointContext) -> int:
    return int(_opts(ctx).get("expires_in", _DEFAULT_EXPIRES_IN))  # type: ignore[arg-type]


def _allowed_attempts(ctx: EndpointContext) -> int:
    return int(_opts(ctx).get("allowed_attempts", 3))  # type: ignore[arg-type]


def generate_otp(length: int = _DEFAULT_LENGTH) -> str:
    if length <= 0:
        raise ValueError("OTP length must be positive")
    upper = 10**length
    return f"{secrets.randbelow(upper):0{length}d}"


def _identifier(phone: str, purpose: str = "sign-in") -> str:
    return f"phone-number:{purpose}:{phone}"


def _now() -> int:
    return int(time.time())


async def _send_sms(ctx: EndpointContext, phone: str, message: str) -> None:
    fn = _opts(ctx).get("send_sms")
    if fn is None:
        raise APIError(
            500,
            "PHONE_NUMBER_NOT_CONFIGURED",
            message="send_sms callable is not configured",
        )
    await fn(phone, message)  # type: ignore[misc]


async def _create_otp(
    ctx: EndpointContext, *, phone: str, purpose: str = "sign-in"
) -> str:
    otp = generate_otp(_otp_length(ctx))
    identifier = _identifier(phone, purpose)
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
    ctx: EndpointContext, *, phone: str, otp: str, purpose: str = "sign-in"
) -> None:
    identifier = _identifier(phone, purpose)
    record = await ctx.auth.adapter.find_one(
        model="verification",
        where=(Where(field="identifier", value=identifier),),
    )
    if not record:
        raise APIError(400, "OTP_NOT_FOUND", message="OTP not found")
    if int(record.get("expiresAt", 0)) < _now():
        await ctx.auth.adapter.delete_many(
            model="verification",
            where=(Where(field="identifier", value=identifier),),
        )
        raise APIError(400, "OTP_EXPIRED", message="OTP has expired")
    stored, _, attempts_str = str(record["value"]).rpartition(":")
    attempts = int(attempts_str or "0")
    if attempts >= _allowed_attempts(ctx):
        await ctx.auth.adapter.delete_many(
            model="verification",
            where=(Where(field="identifier", value=identifier),),
        )
        raise APIError(403, "TOO_MANY_ATTEMPTS")
    if stored != otp:
        await ctx.auth.adapter.update(
            model="verification",
            where=(Where(field="identifier", value=identifier),),
            update={"value": f"{stored}:{attempts + 1}", "updatedAt": _now()},
        )
        raise APIError(400, "INVALID_OTP", message="OTP is invalid")
    await ctx.auth.adapter.delete_many(
        model="verification",
        where=(Where(field="identifier", value=identifier),),
    )


# ---------- request bodies -----------------------------------------------------


class SignInPhoneNumberBody(BaseModel):
    phone_number: str
    password: str
    remember_me: bool = True


class PhoneNumberBody(BaseModel):
    phone_number: str


class VerifyPhoneNumberBody(BaseModel):
    phone_number: str
    # Accept both the Python-native `otp` and the upstream `code` field name.
    otp: str = Field(validation_alias=AliasChoices("otp", "code"))
    disable_session: bool = False


class ResetPasswordBody(BaseModel):
    phone_number: str
    otp: str
    new_password: str


# ---------- handlers -----------------------------------------------------------


async def _sign_in_phone(ctx: EndpointContext) -> dict[str, object]:
    body: SignInPhoneNumberBody = ctx.body
    user = await ctx.auth.adapter.find_one(
        model="user", where=(Where(field="phoneNumber", value=body.phone_number),)
    )
    if not user:
        raise APIError(401, "INVALID_PHONE_NUMBER_OR_PASSWORD")

    opts = _opts(ctx)
    if bool(opts.get("require_verification", False)) and not user.get(
        "phoneNumberVerified"
    ):
        # Mirror upstream: mint + dispatch a fresh OTP, then refuse the sign-in.
        otp = await _create_otp(ctx, phone=body.phone_number, purpose="sign-in")
        send_sms = opts.get("send_sms")
        if send_sms is not None:
            await send_sms(body.phone_number, f"Your code is {otp}")  # type: ignore[misc]
        raise APIError(401, "PHONE_NUMBER_NOT_VERIFIED")

    account = await ctx.auth.adapter.find_one(
        model="account",
        where=(
            Where(field="userId", value=user["id"]),
            Where(field="providerId", value="credential"),
        ),
    )
    if not account or not account.get("password"):
        raise APIError(401, "INVALID_PHONE_NUMBER_OR_PASSWORD")
    if not verify_password(body.password, account["password"]):
        raise APIError(401, "INVALID_PHONE_NUMBER_OR_PASSWORD")
    session, cookies = await create_session(
        ctx.auth,
        user_id=user["id"],
        ip_address=ctx.request.headers.get("x-forwarded-for"),
        user_agent=ctx.request.headers.get("user-agent"),
        remember_me=body.remember_me,
    )
    ctx.set_cookies.extend(cookies)
    return {
        "token": session.token,
        "user": user,
        "session": {"id": session.id, "expiresAt": session.expires_at},
    }


async def _send_otp_handler(ctx: EndpointContext) -> dict[str, object]:
    body: PhoneNumberBody = ctx.body
    otp = await _create_otp(ctx, phone=body.phone_number, purpose="sign-in")
    await _send_sms(ctx, body.phone_number, f"Your code is {otp}")
    return {"success": True}


async def _verify_phone(ctx: EndpointContext) -> dict[str, object]:
    body: VerifyPhoneNumberBody = ctx.body
    await _consume_otp(
        ctx, phone=body.phone_number, otp=body.otp, purpose="sign-in"
    )
    user = await ctx.auth.adapter.find_one(
        model="user", where=(Where(field="phoneNumber", value=body.phone_number),)
    )
    is_new_user = False
    if user is None:
        opts = _opts(ctx)
        if bool(opts.get("disable_sign_up", False)):
            raise APIError(403, "PHONE_NUMBER_SIGN_UP_DISABLED")
        now = _now()
        user = await ctx.auth.adapter.create(
            model="user",
            data={
                # `email` is a required NOT NULL column on the core schema; we
                # synthesize a placeholder so phone-only signups work.
                "email": f"{body.phone_number}@phone.local",
                "emailVerified": False,
                "phoneNumber": body.phone_number,
                "phoneNumberVerified": True,
                "createdAt": now,
                "updatedAt": now,
            },
        )
        is_new_user = True
    elif not user.get("phoneNumberVerified"):
        await ctx.auth.adapter.update(
            model="user",
            where=(Where(field="id", value=user["id"]),),
            update={"phoneNumberVerified": True, "updatedAt": _now()},
        )
        user = {**user, "phoneNumberVerified": True}

    if body.disable_session:
        return {"status": True, "token": None, "user": user, "isNewUser": is_new_user}

    session, cookies = await create_session(
        ctx.auth,
        user_id=user["id"],
        ip_address=ctx.request.headers.get("x-forwarded-for"),
        user_agent=ctx.request.headers.get("user-agent"),
    )
    ctx.set_cookies.extend(cookies)
    return {
        "status": True,
        "token": session.token,
        "user": user,
        "session": {"id": session.id, "expiresAt": session.expires_at},
        "isNewUser": is_new_user,
    }


async def _request_password_reset(ctx: EndpointContext) -> dict[str, object]:
    body: PhoneNumberBody = ctx.body
    user = await ctx.auth.adapter.find_one(
        model="user", where=(Where(field="phoneNumber", value=body.phone_number),)
    )
    if user is not None:
        otp = await _create_otp(
            ctx, phone=body.phone_number, purpose="forget-password"
        )
        await _send_sms(ctx, body.phone_number, f"Password reset code: {otp}")
    return {"success": True}


async def _reset_password(ctx: EndpointContext) -> dict[str, object]:
    body: ResetPasswordBody = ctx.body
    await _consume_otp(
        ctx, phone=body.phone_number, otp=body.otp, purpose="forget-password"
    )
    user = await ctx.auth.adapter.find_one(
        model="user", where=(Where(field="phoneNumber", value=body.phone_number),)
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
    new_hash = hash_password(body.new_password)
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


# ---------- endpoint table -----------------------------------------------------


SIGN_IN_PHONE = create_auth_endpoint(
    "/sign-in/phone-number",
    EndpointOptions(method="POST", body=SignInPhoneNumberBody),
    _sign_in_phone,
)

SEND_OTP = create_auth_endpoint(
    "/phone-number/send-otp",
    EndpointOptions(method="POST", body=PhoneNumberBody),
    _send_otp_handler,
)

VERIFY_OTP = create_auth_endpoint(
    "/phone-number/verify",
    EndpointOptions(method="POST", body=VerifyPhoneNumberBody),
    _verify_phone,
)

REQUEST_PASSWORD_RESET = create_auth_endpoint(
    "/phone-number/request-password-reset",
    EndpointOptions(method="POST", body=PhoneNumberBody),
    _request_password_reset,
)

RESET_PASSWORD = create_auth_endpoint(
    "/phone-number/reset-password",
    EndpointOptions(method="POST", body=ResetPasswordBody),
    _reset_password,
)


ALL: tuple[AuthEndpoint, ...] = (
    SIGN_IN_PHONE,
    SEND_OTP,
    VERIFY_OTP,
    REQUEST_PASSWORD_RESET,
    RESET_PASSWORD,
)
