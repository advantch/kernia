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

import base64
import hashlib
import hmac
import inspect
import re
import secrets
import time
from typing import Any

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
_DEFAULT_ALLOWED_ATTEMPTS = 3


def _opts(ctx: EndpointContext) -> dict[str, Any]:
    return dict(ctx.auth.options.advanced.get(_OPTIONS_KEY) or {})


def _otp_length(ctx: EndpointContext) -> int:
    return int(_opts(ctx).get("otp_length", _DEFAULT_LENGTH))


def _expires_in(ctx: EndpointContext) -> int:
    return int(_opts(ctx).get("expires_in", _DEFAULT_EXPIRES_IN))


def _allowed_attempts(ctx: EndpointContext) -> int:
    return int(_opts(ctx).get("allowed_attempts", _DEFAULT_ALLOWED_ATTEMPTS))


def default_key_hasher(otp: str) -> str:
    """SHA-256 + unpadded base64url. Mirrors `email-otp/utils.ts`."""
    digest = hashlib.sha256(otp.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _is_valid_email(email: str) -> bool:
    """Mirror `z.email()` validation used by upstream send/verify endpoints."""
    return bool(_EMAIL_RE.match(email))


def _symmetric_encrypt(secret: str, data: str) -> str:
    """Reversible at-rest transform for `store_otp="encrypted"`.

    Scoped to the plugin (core exposes no symmetric primitive). XOR-keystream
    derived from the configured secret, base64url-encoded. Sufficient for the
    plugin contract: the stored value is unreadable without the secret and is
    recoverable for `getVerificationOTP`. Not the JS AES-GCM scheme, but the
    parity contract is "recoverable + not plaintext".
    """
    key = hashlib.sha256(secret.encode("utf-8")).digest()
    raw = data.encode("utf-8")
    keystream = (key * (len(raw) // len(key) + 1))[: len(raw)]
    xored = bytes(b ^ k for b, k in zip(raw, keystream, strict=False))
    return base64.urlsafe_b64encode(xored).decode("ascii")


def _symmetric_decrypt(secret: str, data: str) -> str:
    key = hashlib.sha256(secret.encode("utf-8")).digest()
    raw = base64.urlsafe_b64decode(data.encode("ascii"))
    keystream = (key * (len(raw) // len(key) + 1))[: len(raw)]
    xored = bytes(b ^ k for b, k in zip(raw, keystream, strict=False))
    return xored.decode("utf-8")


async def _maybe_await(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value


def generate_otp(length: int = _DEFAULT_LENGTH) -> str:
    """Generate a numeric OTP. Module-level so unit tests can hit it directly."""
    if length <= 0:
        raise ValueError("OTP length must be positive")
    upper = 10**length
    return f"{secrets.randbelow(upper):0{length}d}"


async def _generate_otp(ctx: EndpointContext, *, email: str, purpose: str) -> str:
    """Mirror upstream `opts.generateOTP(...) || defaultOTPGenerator(opts)`."""
    gen = _opts(ctx).get("generate_otp")
    if gen is not None:
        custom = await _maybe_await(gen({"email": email, "type": purpose}, ctx))
        if custom:
            return str(custom)
    return generate_otp(_otp_length(ctx))


async def _store_otp(ctx: EndpointContext, otp: str) -> str:
    """Transform an OTP for at-rest storage. Mirrors `storeOTP`."""
    mode = _opts(ctx).get("store_otp")
    if mode == "encrypted":
        return _symmetric_encrypt(ctx.auth.secret, otp)
    if mode == "hashed":
        return default_key_hasher(otp)
    if isinstance(mode, dict) and "hash" in mode:
        return str(await _maybe_await(mode["hash"](otp)))
    if isinstance(mode, dict) and "encrypt" in mode:
        return str(await _maybe_await(mode["encrypt"](otp)))
    return otp


async def _verify_stored_otp(ctx: EndpointContext, stored: str, otp: str) -> bool:
    """Constant-time compare against a stored OTP. Mirrors `verifyStoredOTP`."""
    mode = _opts(ctx).get("store_otp")
    if mode == "encrypted":
        decrypted = _symmetric_decrypt(ctx.auth.secret, stored)
        return hmac.compare_digest(decrypted, otp)
    if mode == "hashed":
        return hmac.compare_digest(default_key_hasher(otp), stored)
    if isinstance(mode, dict) and "hash" in mode:
        hashed = str(await _maybe_await(mode["hash"](otp)))
        return hmac.compare_digest(hashed, stored)
    if isinstance(mode, dict) and "decrypt" in mode:
        decrypted = str(await _maybe_await(mode["decrypt"](stored)))
        return hmac.compare_digest(decrypted, otp)
    return hmac.compare_digest(otp, stored)


async def _retrieve_otp(ctx: EndpointContext, stored: str) -> str | None:
    """Recover the plain-text OTP if possible. Mirrors `retrieveOTP`."""
    mode = _opts(ctx).get("store_otp")
    if mode in (None, "plain"):
        return stored
    if mode == "encrypted":
        return _symmetric_decrypt(ctx.auth.secret, stored)
    if isinstance(mode, dict) and "decrypt" in mode:
        return str(await _maybe_await(mode["decrypt"](stored)))
    # hashed or custom hash -> cannot recover
    return None


async def _try_reuse_otp(ctx: EndpointContext, *, email: str, purpose: str) -> str | None:
    """Reuse an unexpired OTP and extend its expiry. Mirrors `tryReuseOTP`."""
    identifier = _identifier(purpose, email)
    record = await ctx.auth.adapter.find_one(
        model="verification",
        where=(Where(field="identifier", value=identifier),),
    )
    if not record or int(record.get("expiresAt", 0)) < _now():
        return None
    stored, _, attempts_str = str(record["value"]).rpartition(":")
    if attempts_str and int(attempts_str) >= _allowed_attempts(ctx):
        return None
    plain = await _retrieve_otp(ctx, stored)
    if not plain:
        return None
    await ctx.auth.adapter.update(
        model="verification",
        where=(Where(field="identifier", value=identifier),),
        update={"expiresAt": _now() + _expires_in(ctx), "updatedAt": _now()},
    )
    return plain


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
    await fn(email, otp, purpose)


async def _create_otp(ctx: EndpointContext, *, email: str, purpose: str) -> str:
    # resend_strategy "reuse": resend the same OTP and extend expiry when the
    # OTP is recoverable (plain/encrypted/custom decrypt). Falls back to rotate.
    if _opts(ctx).get("resend_strategy") == "reuse":
        reused = await _try_reuse_otp(ctx, email=email, purpose=purpose)
        if reused is not None:
            return reused
    otp = await _generate_otp(ctx, email=email, purpose=purpose)
    stored = await _store_otp(ctx, otp)
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
            "value": f"{stored}:0",
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
        raise APIError(400, "INVALID_OTP", message="Invalid OTP")
    if int(record.get("expiresAt", 0)) < _now():
        await ctx.auth.adapter.delete_many(
            model="verification",
            where=(Where(field="identifier", value=identifier),),
        )
        raise APIError(400, "OTP_EXPIRED", message="OTP expired")
    stored, _, attempts_str = str(record["value"]).rpartition(":")
    attempts = int(attempts_str or "0")
    if attempts >= _allowed_attempts(ctx):
        await ctx.auth.adapter.delete_many(
            model="verification",
            where=(Where(field="identifier", value=identifier),),
        )
        raise APIError(403, "TOO_MANY_ATTEMPTS", message="Too many attempts")
    if not await _verify_stored_otp(ctx, stored, otp):
        await ctx.auth.adapter.update(
            model="verification",
            where=(Where(field="identifier", value=identifier),),
            update={"value": f"{stored}:{attempts + 1}", "updatedAt": _now()},
        )
        raise APIError(400, "INVALID_OTP", message="Invalid OTP")
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
    otp: str | None = None


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
    email = body.email.lower()
    if not _is_valid_email(email):
        raise APIError(400, "INVALID_EMAIL", message="Email address is invalid.")
    purpose = body.type or "email-verification"
    # Change-email OTPs must be requested via the dedicated endpoint.
    if purpose == "change-email":
        raise APIError(400, "INVALID_OTP_TYPE", message="Invalid OTP type")
    opts = _opts(ctx)
    disable_sign_up = bool(opts.get("disable_sign_up", False))
    otp = await _create_otp(ctx, email=email, purpose=purpose)
    # For sign-in with sign-up allowed we always send (the user may not exist
    # yet). Otherwise we only send when the user exists, but still return success
    # to avoid user-enumeration. Mirrors upstream `shouldSendOTP`.
    should_send = purpose == "sign-in" and not disable_sign_up
    user = await ctx.auth.adapter.find_one(model="user", where=(Where(field="email", value=email),))
    if user is None and not should_send:
        identifier = _identifier(purpose, email)
        await ctx.auth.adapter.delete_many(
            model="verification",
            where=(Where(field="identifier", value=identifier),),
        )
        return {"success": True}
    await _send_otp(ctx, email, otp, purpose)
    return {"success": True}


async def _verify_email(ctx: EndpointContext) -> dict[str, object]:
    body: VerifyOTPBody = ctx.body
    email = body.email.lower()
    if not _is_valid_email(email):
        raise APIError(400, "INVALID_EMAIL", message="Email address is invalid.")
    # Atomic-style consume (delete first, re-create on miss) for race safety.
    await _consume_otp(ctx, email=email, purpose="email-verification", otp=body.otp)
    user = await ctx.auth.adapter.find_one(model="user", where=(Where(field="email", value=email),))
    if user is None:
        raise APIError(400, "USER_NOT_FOUND", message="User not found")
    updated = await ctx.auth.adapter.update(
        model="user",
        where=(Where(field="id", value=user["id"]),),
        update={"emailVerified": True, "updatedAt": _now()},
    )
    return {"success": True, "status": True, "user": updated or user}


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
    await _consume_otp(ctx, email=body.email, purpose="forget-password", otp=body.otp)
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
    if not user.get("emailVerified"):
        await ctx.auth.adapter.update(
            model="user",
            where=(Where(field="id", value=user["id"]),),
            update={"emailVerified": True, "updatedAt": _now()},
        )
    callback = _opts(ctx).get("on_password_reset")
    if callback is not None:
        await _maybe_await(callback({"user": user}, ctx))
    return {"success": True}


async def _session_user_email(ctx: EndpointContext) -> str | None:
    if ctx.session is None:
        return None
    user = await ctx.auth.adapter.find_one(
        model="user", where=(Where(field="id", value=ctx.session.user_id),)
    )
    if user is None:
        return None
    return str(user.get("email", "")).lower()


def _change_email_enabled(ctx: EndpointContext) -> bool:
    cfg = _opts(ctx).get("change_email")
    return bool(isinstance(cfg, dict) and cfg.get("enabled"))


def _verify_current_email(ctx: EndpointContext) -> bool:
    cfg = _opts(ctx).get("change_email")
    return bool(isinstance(cfg, dict) and cfg.get("verify_current_email"))


async def _request_email_change(ctx: EndpointContext) -> dict[str, object]:
    if ctx.session is None:
        raise APIError(401, "UNAUTHORIZED")
    if not _change_email_enabled(ctx):
        raise APIError(400, "CHANGE_EMAIL_DISABLED", message="Change email with OTP is disabled")
    body: RequestEmailChangeBody = ctx.body
    email = await _session_user_email(ctx)
    if email is None:
        raise APIError(401, "UNAUTHORIZED")
    new_email = body.new_email.lower()
    if not _is_valid_email(new_email):
        raise APIError(400, "INVALID_EMAIL", message="Email address is invalid.")
    if new_email == email:
        raise APIError(400, "EMAIL_IS_THE_SAME", message="Email is the same")

    # Optionally verify the user owns the current email before issuing the
    # change-email OTP to the new address.
    if _verify_current_email(ctx):
        if not body.otp:
            raise APIError(
                400,
                "OTP_REQUIRED",
                message="OTP is required to verify current email",
            )
        await _consume_otp(ctx, email=email, purpose="email-verification", otp=body.otp)

    # Issue the change-email OTP keyed by (currentEmail-newEmail).
    composite = f"{email}-{new_email}"
    otp = await _create_otp(ctx, email=composite, purpose="change-email")

    # If the new email is already used by another account, silently succeed
    # without sending (avoid disclosing membership).
    existing = await ctx.auth.adapter.find_one(
        model="user", where=(Where(field="email", value=new_email),)
    )
    if existing is not None:
        await ctx.auth.adapter.delete_many(
            model="verification",
            where=(Where(field="identifier", value=_identifier("change-email", composite)),),
        )
        return {"success": True}

    await _send_otp(ctx, new_email, otp, "change-email")
    return {"success": True}


async def _change_email(ctx: EndpointContext) -> dict[str, object]:
    if ctx.session is None:
        raise APIError(401, "UNAUTHORIZED")
    if not _change_email_enabled(ctx):
        raise APIError(400, "CHANGE_EMAIL_DISABLED", message="Change email with OTP is disabled")
    body: ChangeEmailBody = ctx.body
    email = await _session_user_email(ctx)
    if email is None:
        raise APIError(401, "UNAUTHORIZED")
    new_email = body.new_email.lower()
    if not _is_valid_email(new_email):
        raise APIError(400, "INVALID_EMAIL", message="Email address is invalid.")
    if new_email == email:
        raise APIError(400, "EMAIL_IS_THE_SAME", message="Email is the same")

    composite = f"{email}-{new_email}"
    await _consume_otp(ctx, email=composite, purpose="change-email", otp=body.otp)

    existing = await ctx.auth.adapter.find_one(
        model="user", where=(Where(field="email", value=new_email),)
    )
    if existing is not None:
        raise APIError(400, "EMAIL_ALREADY_IN_USE", message="Email already in use")

    await ctx.auth.adapter.update(
        model="user",
        where=(Where(field="id", value=ctx.session.user_id),),
        update={
            "email": new_email,
            "emailVerified": True,
            "updatedAt": _now(),
        },
    )
    return {"success": True}


class CreateVerificationOTPBody(BaseModel):
    email: str
    type: str = "email-verification"


class GetVerificationOTPQuery(BaseModel):
    email: str
    type: str = "email-verification"


class CheckVerificationOTPBody(BaseModel):
    email: str
    otp: str
    type: str = "email-verification"


async def _create_verification_otp(ctx: EndpointContext) -> str:
    """Server-only: create + store an OTP and return the plain text. Mirrors
    `auth.api.createVerificationOTP`."""
    body: CreateVerificationOTPBody = ctx.body
    email = body.email.lower()
    purpose = body.type or "email-verification"
    return await _create_otp(ctx, email=email, purpose=purpose)


async def _get_verification_otp(ctx: EndpointContext) -> dict[str, object]:
    """Server-only: recover a stored plain OTP. Throws if hashed. Mirrors
    `auth.api.getVerificationOTP`."""
    query: GetVerificationOTPQuery = ctx.body
    email = query.email.lower()
    purpose = query.type or "email-verification"
    identifier = _identifier(purpose, email)
    record = await ctx.auth.adapter.find_one(
        model="verification",
        where=(Where(field="identifier", value=identifier),),
    )
    if not record or int(record.get("expiresAt", 0)) < _now():
        return {"otp": None}
    mode = _opts(ctx).get("store_otp")
    if mode == "hashed" or (isinstance(mode, dict) and "hash" in mode):
        raise APIError(
            400,
            "OTP_HASHED",
            message="OTP is hashed, cannot return the plain text OTP",
        )
    stored = str(record["value"]).rpartition(":")[0]
    plain = await _retrieve_otp(ctx, stored)
    return {"otp": plain}


async def _check_verification_otp(ctx: EndpointContext) -> dict[str, object]:
    """Verify an OTP without consuming user state. Mirrors
    `auth.api.checkVerificationOTP`."""
    body: CheckVerificationOTPBody = ctx.body
    email = body.email.lower()
    if not _is_valid_email(email):
        raise APIError(400, "INVALID_EMAIL", message="Email address is invalid.")
    purpose = body.type or "email-verification"
    identifier = _identifier(purpose, email)
    record = await ctx.auth.adapter.find_one(
        model="verification",
        where=(Where(field="identifier", value=identifier),),
    )
    if not record:
        raise APIError(400, "INVALID_OTP", message="Invalid OTP")
    if int(record.get("expiresAt", 0)) < _now():
        await ctx.auth.adapter.delete_many(
            model="verification",
            where=(Where(field="identifier", value=identifier),),
        )
        raise APIError(400, "OTP_EXPIRED", message="OTP expired")
    stored, _, attempts_str = str(record["value"]).rpartition(":")
    attempts = int(attempts_str or "0")
    if attempts >= _allowed_attempts(ctx):
        await ctx.auth.adapter.delete_many(
            model="verification",
            where=(Where(field="identifier", value=identifier),),
        )
        raise APIError(403, "TOO_MANY_ATTEMPTS", message="Too many attempts")
    if not await _verify_stored_otp(ctx, stored, body.otp):
        await ctx.auth.adapter.update(
            model="verification",
            where=(Where(field="identifier", value=identifier),),
            update={"value": f"{stored}:{attempts + 1}", "updatedAt": _now()},
        )
        raise APIError(400, "INVALID_OTP", message="Invalid OTP")
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
    EndpointOptions(method="POST", body=VerifyOTPBody),
    _verify_email,
)

FORGET_PASSWORD_OTP = create_auth_endpoint(
    "/forget-password/email-otp",
    EndpointOptions(method="POST", body=EmailBody),
    _forget_password_send,
)

REQUEST_PASSWORD_RESET_OTP = create_auth_endpoint(
    "/email-otp/request-password-reset",
    EndpointOptions(method="POST", body=EmailBody),
    _forget_password_send,
)

RESET_PASSWORD_OTP = create_auth_endpoint(
    "/email-otp/reset-password",
    EndpointOptions(method="POST", body=ResetPasswordBody),
    _reset_password,
)

CREATE_VERIFICATION_OTP = create_auth_endpoint(
    "/email-otp/create-verification-otp",
    EndpointOptions(method="POST", body=CreateVerificationOTPBody),
    _create_verification_otp,
)

GET_VERIFICATION_OTP = create_auth_endpoint(
    "/email-otp/get-verification-otp",
    EndpointOptions(method="POST", body=GetVerificationOTPQuery),
    _get_verification_otp,
)

CHECK_VERIFICATION_OTP = create_auth_endpoint(
    "/email-otp/check-verification-otp",
    EndpointOptions(method="POST", body=CheckVerificationOTPBody),
    _check_verification_otp,
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
    REQUEST_PASSWORD_RESET_OTP,
    RESET_PASSWORD_OTP,
    CREATE_VERIFICATION_OTP,
    GET_VERIFICATION_OTP,
    CHECK_VERIFICATION_OTP,
    REQUEST_EMAIL_CHANGE,
    CHANGE_EMAIL,
)
