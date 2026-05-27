"""Two-factor plugin endpoint handlers.

Mirrors `reference/packages/better-auth/src/plugins/two-factor/`. Implements TOTP
plus single-use backup codes. The plugin contributes two new tables:

  * `twoFactorConfirmation` — pending TOTP challenges between password and code step
  * `twoFactorBackupCode`   — hashed one-time codes
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass
from urllib.parse import quote

from kernia.api.endpoint import create_auth_endpoint
from kernia.context import create_session
from kernia.crypto import hash_password, verify_password
from kernia.error import APIError
from kernia.types.adapter import Where
from kernia.types.context import EndpointContext
from kernia.types.endpoint import AuthEndpoint, EndpointOptions


CONFIRMATION_TTL_SECONDS = 5 * 60  # 5 min window between password step and TOTP step


# ----- request body shapes -----


@dataclass(frozen=True, slots=True)
class EnableBody:
    password: str  # re-confirm password
    issuer: str | None = None


@dataclass(frozen=True, slots=True)
class VerifyTotpBody:
    code: str
    confirmation_id: str | None = None
    trust_device: bool = False


@dataclass(frozen=True, slots=True)
class DisableBody:
    password: str


@dataclass(frozen=True, slots=True)
class VerifyBackupCodeBody:
    code: str
    confirmation_id: str | None = None


# ----- helpers -----


def _require_pyotp() -> object:
    try:
        import pyotp
    except ImportError as exc:  # pragma: no cover
        raise APIError(500, "INTERNAL", message=f"pyotp not installed: {exc}") from exc
    return pyotp


def _check_session_password(ctx: EndpointContext, password: str) -> dict[str, object]:
    if ctx.session is None:
        raise APIError(401, "UNAUTHORIZED")
    return _verify_pw_for_user(ctx, ctx.session.user_id, password)


def _verify_pw_for_user(
    ctx: EndpointContext, user_id: str, password: str
) -> dict[str, object]:
    import asyncio  # noqa: F401 — keep async ergonomics clear
    # Not async itself — caller awaits.
    raise NotImplementedError


async def _load_account(ctx: EndpointContext, user_id: str) -> dict[str, object] | None:
    return await ctx.auth.adapter.find_one(
        model="account",
        where=(
            Where(field="userId", value=user_id),
            Where(field="providerId", value="credential"),
        ),
    )


# ----- handlers -----


async def _enable(ctx: EndpointContext) -> dict[str, object]:
    if ctx.session is None:
        raise APIError(401, "UNAUTHORIZED")
    body: EnableBody = ctx.body
    account = await _load_account(ctx, ctx.session.user_id)
    if not account or not account.get("password"):
        raise APIError(401, "INVALID_CREDENTIALS")
    if not verify_password(body.password, account["password"]):
        raise APIError(401, "INVALID_CREDENTIALS")

    pyotp = _require_pyotp()
    secret = pyotp.random_base32()  # type: ignore[attr-defined]
    # Stash the secret pending verification — we don't flip twoFactorEnabled
    # until the user proves they can produce a valid TOTP code.
    await ctx.auth.adapter.update(
        model="user",
        where=(Where(field="id", value=ctx.session.user_id),),
        update={"twoFactorSecret": secret, "twoFactorEnabled": False},
    )
    user = await ctx.auth.adapter.find_one(
        model="user",
        where=(Where(field="id", value=ctx.session.user_id),),
    )
    assert user is not None
    issuer = body.issuer or "better-auth"
    label = quote(user.get("email") or user["id"], safe="")
    otpauth = (
        f"otpauth://totp/{issuer}:{label}?secret={secret}&issuer={quote(issuer)}"
    )
    return {"secret": secret, "otpauth_url": otpauth}


async def _verify_totp(ctx: EndpointContext) -> dict[str, object]:
    body: VerifyTotpBody = ctx.body
    pyotp = _require_pyotp()
    now_ts = int(time.time())

    # Two flows: (a) confirmation_id → mid-sign-in promotion, (b) authenticated → finalize enable.
    if body.confirmation_id:
        confirmation = await ctx.auth.adapter.find_one(
            model="twoFactorConfirmation",
            where=(Where(field="id", value=body.confirmation_id),),
        )
        if not confirmation or int(confirmation.get("expiresAt", 0)) < now_ts:
            raise APIError(401, "INVALID_TWO_FACTOR_CONFIRMATION")
        user_id = confirmation["userId"]
    else:
        if ctx.session is None:
            raise APIError(401, "UNAUTHORIZED")
        user_id = ctx.session.user_id

    user = await ctx.auth.adapter.find_one(
        model="user",
        where=(Where(field="id", value=user_id),),
    )
    if not user or not user.get("twoFactorSecret"):
        raise APIError(400, "TWO_FACTOR_NOT_ENABLED")

    totp = pyotp.TOTP(user["twoFactorSecret"])  # type: ignore[attr-defined]
    # `valid_window=0` keeps the test "old code rejected" honest by default.
    if not totp.verify(body.code, valid_window=0):
        raise APIError(401, "INVALID_TWO_FACTOR_CODE")

    # Flip the enabled bit on the first successful verify.
    if not user.get("twoFactorEnabled"):
        await ctx.auth.adapter.update(
            model="user",
            where=(Where(field="id", value=user_id),),
            update={"twoFactorEnabled": True},
        )

    response: dict[str, object] = {"success": True}
    if body.confirmation_id:
        # Promote the confirmation → real session.
        await ctx.auth.adapter.delete(
            model="twoFactorConfirmation",
            where=(Where(field="id", value=body.confirmation_id),),
        )
        session, cookies = await create_session(
            ctx.auth,
            user_id=user_id,
            ip_address=ctx.request.headers.get("x-forwarded-for"),
            user_agent=ctx.request.headers.get("user-agent"),
        )
        ctx.set_cookies.extend(cookies)
        response["session"] = {"id": session.id, "expiresAt": session.expires_at}
    return response


async def _disable(ctx: EndpointContext) -> dict[str, object]:
    if ctx.session is None:
        raise APIError(401, "UNAUTHORIZED")
    body: DisableBody = ctx.body
    account = await _load_account(ctx, ctx.session.user_id)
    if not account or not account.get("password") or not verify_password(
        body.password, account["password"]
    ):
        raise APIError(401, "INVALID_CREDENTIALS")
    await ctx.auth.adapter.update(
        model="user",
        where=(Where(field="id", value=ctx.session.user_id),),
        update={"twoFactorEnabled": False, "twoFactorSecret": None},
    )
    await ctx.auth.adapter.delete_many(
        model="twoFactorBackupCode",
        where=(Where(field="userId", value=ctx.session.user_id),),
    )
    return {"success": True}


async def _generate_backup_codes(ctx: EndpointContext) -> dict[str, object]:
    if ctx.session is None:
        raise APIError(401, "UNAUTHORIZED")
    # Replace any existing codes.
    await ctx.auth.adapter.delete_many(
        model="twoFactorBackupCode",
        where=(Where(field="userId", value=ctx.session.user_id),),
    )
    codes: list[str] = []
    for _ in range(8):
        # Format: "XXXX-XXXX" — human-friendly, 32 bits of entropy.
        code = f"{secrets.token_hex(2)}-{secrets.token_hex(2)}"
        codes.append(code)
        await ctx.auth.adapter.create(
            model="twoFactorBackupCode",
            data={
                "userId": ctx.session.user_id,
                "codeHash": hash_password(code),
                "used": False,
            },
        )
    return {"backup_codes": codes}


async def _verify_backup_code(ctx: EndpointContext) -> dict[str, object]:
    body: VerifyBackupCodeBody = ctx.body
    if body.confirmation_id:
        confirmation = await ctx.auth.adapter.find_one(
            model="twoFactorConfirmation",
            where=(Where(field="id", value=body.confirmation_id),),
        )
        if not confirmation:
            raise APIError(401, "INVALID_TWO_FACTOR_CONFIRMATION")
        user_id = confirmation["userId"]
    else:
        if ctx.session is None:
            raise APIError(401, "UNAUTHORIZED")
        user_id = ctx.session.user_id

    rows = await ctx.auth.adapter.find_many(
        model="twoFactorBackupCode",
        where=(
            Where(field="userId", value=user_id),
            Where(field="used", value=False),
        ),
    )
    matched_id: str | None = None
    for row in rows:
        if verify_password(body.code, row["codeHash"]):
            matched_id = row["id"]
            break
    if matched_id is None:
        raise APIError(401, "INVALID_BACKUP_CODE")

    await ctx.auth.adapter.update(
        model="twoFactorBackupCode",
        where=(Where(field="id", value=matched_id),),
        update={"used": True},
    )
    response: dict[str, object] = {"success": True}
    if body.confirmation_id:
        await ctx.auth.adapter.delete(
            model="twoFactorConfirmation",
            where=(Where(field="id", value=body.confirmation_id),),
        )
        session, cookies = await create_session(
            ctx.auth,
            user_id=user_id,
            ip_address=ctx.request.headers.get("x-forwarded-for"),
            user_agent=ctx.request.headers.get("user-agent"),
        )
        ctx.set_cookies.extend(cookies)
        response["session"] = {"id": session.id, "expiresAt": session.expires_at}
    return response


ENABLE = create_auth_endpoint(
    "/two-factor/enable",
    EndpointOptions(method="POST", body=EnableBody, requires_session=True),
    _enable,
)
VERIFY_TOTP = create_auth_endpoint(
    "/two-factor/verify-totp",
    EndpointOptions(method="POST", body=VerifyTotpBody),
    _verify_totp,
)
DISABLE = create_auth_endpoint(
    "/two-factor/disable",
    EndpointOptions(method="POST", body=DisableBody, requires_session=True),
    _disable,
)
GENERATE_BACKUP_CODES = create_auth_endpoint(
    "/two-factor/generate-backup-codes",
    EndpointOptions(method="POST", requires_session=True),
    _generate_backup_codes,
)
VERIFY_BACKUP_CODE = create_auth_endpoint(
    "/two-factor/verify-backup-code",
    EndpointOptions(method="POST", body=VerifyBackupCodeBody),
    _verify_backup_code,
)


ALL: tuple[AuthEndpoint, ...] = (
    ENABLE,
    VERIFY_TOTP,
    DISABLE,
    GENERATE_BACKUP_CODES,
    VERIFY_BACKUP_CODE,
)
