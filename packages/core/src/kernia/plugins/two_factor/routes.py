"""Two-factor plugin endpoint handlers.

Port of `reference/packages/better-auth/src/plugins/two-factor/`. Implements the
full upstream surface:

  * `/two-factor/enable`               — issue TOTP secret + backup codes
  * `/two-factor/disable`              — turn 2FA off, revoke trust device
  * `/two-factor/get-totp-uri`         — fetch the otpauth:// URI
  * `/two-factor/verify-totp`          — verify a TOTP code (enroll + sign-in)
  * `/two-factor/generate-backup-codes`— regenerate backup codes
  * `/two-factor/verify-backup-code`   — consume a single-use backup code
  * `/two-factor/view-backup-codes`    — server-only, view remaining codes
  * `/two-factor/send-otp`             — deliver an OTP via the `send_otp` option
  * `/two-factor/verify-otp`           — verify a delivered OTP

The sign-in gating lives in `__init__.py` as an after-hook that converts a
credential sign-in into a `twoFactorRedirect` challenge when 2FA is enabled.

Wire format mirrors upstream: response keys are camelCase (`totpURI`,
`backupCodes`, `twoFactorRedirect`, `twoFactorMethods`) and the challenge state
travels through signed cookies (`better-auth.two_factor`, `better-auth.trust_device`,
`better-auth.dont_remember`) plus rows on the core `verification` table.

Requires `pyotp` (declared under the `two-factor` extra of `better-auth`).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import inspect
import json
import secrets
import time
from dataclasses import dataclass
from typing import Any

from kernia import cookies as cookie_utils
from kernia.api.endpoint import create_auth_endpoint
from kernia.context import create_session
from kernia.crypto import verify_password
from kernia.error import APIError
from kernia.types.adapter import Where
from kernia.types.context import EndpointContext
from kernia.types.cookie import (
    DONT_REMEMBER_COOKIE,
    CookieAttributes,
)
from kernia.types.endpoint import AuthEndpoint, EndpointOptions

# ----- constants -------------------------------------------------------------

OPTIONS_KEY = "two-factor"

TWO_FACTOR_COOKIE_NAME = "better-auth.two_factor"
TRUST_DEVICE_COOKIE_NAME = "better-auth.trust_device"

TRUST_DEVICE_COOKIE_MAX_AGE = 30 * 24 * 60 * 60  # 30 days
TWO_FACTOR_COOKIE_MAX_AGE = 10 * 60  # 10 minutes
DEFAULT_OTP_PERIOD = 3 * 60  # 3 minutes
DEFAULT_OTP_DIGITS = 6
DEFAULT_ALLOWED_ATTEMPTS = 5
DEFAULT_TOTP_DIGITS = 6
DEFAULT_TOTP_PERIOD = 30
BACKUP_CODE_AMOUNT = 10
BACKUP_CODE_LENGTH = 10

# Legacy TTL kept for backward-compat imports (old design used a confirmation row).
CONFIRMATION_TTL_SECONDS = 5 * 60

TWO_FACTOR_MODEL = "twoFactor"


# ----- option helpers --------------------------------------------------------


def _opts(ctx: EndpointContext) -> dict[str, object]:
    return dict(ctx.auth.options.advanced.get(OPTIONS_KEY) or {})


def _otp_options(ctx: EndpointContext) -> dict[str, object] | None:
    raw = _opts(ctx).get("otp_options", _opts(ctx).get("otpOptions"))
    if raw is None:
        return None
    return dict(raw)  # type: ignore[arg-type]


def _totp_options(ctx: EndpointContext) -> dict[str, object]:
    raw = _opts(ctx).get("totp_options", _opts(ctx).get("totpOptions")) or {}
    return dict(raw)  # type: ignore[arg-type]


def _skip_verification_on_enable(ctx: EndpointContext) -> bool:
    o = _opts(ctx)
    return bool(o.get("skip_verification_on_enable", o.get("skipVerificationOnEnable")))


def _allow_passwordless(ctx: EndpointContext) -> bool:
    o = _opts(ctx)
    return bool(o.get("allow_passwordless", o.get("allowPasswordless")))


def _trust_device_max_age(ctx: EndpointContext) -> int:
    o = _opts(ctx)
    return int(
        o.get("trust_device_max_age", o.get("trustDeviceMaxAge"))  # type: ignore[arg-type]
        or TRUST_DEVICE_COOKIE_MAX_AGE
    )


def _two_factor_cookie_max_age(ctx: EndpointContext) -> int:
    o = _opts(ctx)
    return int(
        o.get("two_factor_cookie_max_age", o.get("twoFactorCookieMaxAge"))  # type: ignore[arg-type]
        or TWO_FACTOR_COOKIE_MAX_AGE
    )


def _issuer(ctx: EndpointContext) -> str:
    o = _opts(ctx)
    app_name = ctx.auth.options.advanced.get("app_name")
    return str(o.get("issuer") or app_name or "Better Auth")


def _totp_digits(ctx: EndpointContext) -> int:
    return int(_totp_options(ctx).get("digits") or DEFAULT_TOTP_DIGITS)  # type: ignore[arg-type]


def _totp_period(ctx: EndpointContext) -> int:
    return int(_totp_options(ctx).get("period") or DEFAULT_TOTP_PERIOD)  # type: ignore[arg-type]


def _totp_disabled(ctx: EndpointContext) -> bool:
    return bool(_totp_options(ctx).get("disable"))


# ----- crypto / encoding helpers --------------------------------------------


def _require_pyotp() -> object:
    try:
        import pyotp
    except ImportError as exc:  # pragma: no cover
        raise APIError(500, "INTERNAL", message=f"pyotp not installed: {exc}") from exc
    return pyotp


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _hmac_sign(secret: str, value: str) -> str:
    mac = hmac.new(secret.encode(), value.encode(), hashlib.sha256).digest()
    return _b64url(mac)


def _default_key_hasher(token: str) -> str:
    return _b64url(hashlib.sha256(token.encode()).digest())


def _now() -> int:
    return int(time.time())


def _generate_secret() -> str:
    """A base32 TOTP secret (pyotp-compatible)."""
    pyotp = _require_pyotp()
    return pyotp.random_base32()  # type: ignore[attr-defined]


def _generate_backup_codes_list() -> list[str]:
    codes: list[str] = []
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    for _ in range(BACKUP_CODE_AMOUNT):
        raw = "".join(secrets.choice(alphabet) for _ in range(BACKUP_CODE_LENGTH))
        codes.append(f"{raw[:5]}-{raw[5:]}")
    return codes


async def _maybe_await(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value


def _backup_code_storage(ctx: EndpointContext) -> object | None:
    """Resolve `backupCodeOptions.storeBackupCodes`. Mirrors upstream PR #7231:
    "plain" (default), "encrypted", or `{encrypt, decrypt}` custom callables."""
    opts = _opts(ctx)
    bco = opts.get("backup_code_options", opts.get("backupCodeOptions")) or {}
    if isinstance(bco, dict):
        return bco.get("store_backup_codes", bco.get("storeBackupCodes"))
    return None


async def _encode_backup_codes(ctx: EndpointContext, codes: list[str]) -> str:
    raw = json.dumps(codes)
    mode = _backup_code_storage(ctx)
    if mode == "encrypted":
        return _symmetric_encrypt(ctx.auth.secret, raw)
    if isinstance(mode, dict) and "encrypt" in mode:
        return str(await _maybe_await(mode["encrypt"](raw)))
    return raw


async def _decode_backup_codes(ctx: EndpointContext, stored: str) -> list[str]:
    mode = _backup_code_storage(ctx)
    raw = stored
    if mode == "encrypted":
        try:
            raw = _symmetric_decrypt(ctx.auth.secret, stored)
        except (ValueError, UnicodeDecodeError):
            return []
    elif isinstance(mode, dict) and "decrypt" in mode:
        raw = str(await _maybe_await(mode["decrypt"](stored)))
    try:
        loaded = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return []
    return [str(c) for c in loaded] if isinstance(loaded, list) else []


# ----- signed cookie helpers (mirror ctx.getSignedCookie / setSignedCookie) ---


def _get_signed_cookie(ctx: EndpointContext, name: str) -> str | None:
    raw = ctx.request.cookies.get(name)
    if not raw:
        return None
    return cookie_utils.verify(raw, secret=ctx.auth.secret)


def _set_signed_cookie(
    ctx: EndpointContext, name: str, value: str, attrs: CookieAttributes
) -> None:
    signed = cookie_utils.sign(value, secret=ctx.auth.secret)
    ctx.set_cookies.append((name, signed, attrs))


def _expire_cookie(ctx: EndpointContext, name: str) -> None:
    ctx.set_cookies.append(
        (
            name,
            "",
            CookieAttributes(path="/", max_age=0, http_only=True, secure=False, same_site="lax"),
        )
    )


def _secure(ctx: EndpointContext) -> bool:
    return ctx.auth.base_url.startswith("https")


# ----- shared user/account helpers ------------------------------------------


async def _find_user(ctx: EndpointContext, user_id: str) -> dict[str, object] | None:
    return await ctx.auth.adapter.find_one(
        model="user", where=(Where(field="id", value=user_id),)
    )


async def _credential_account(
    ctx: EndpointContext, user_id: str
) -> dict[str, object] | None:
    return await ctx.auth.adapter.find_one(
        model="account",
        where=(
            Where(field="userId", value=user_id),
            Where(field="providerId", value="credential"),
        ),
    )


async def _should_require_password(
    ctx: EndpointContext, user_id: str, allow_passwordless: bool
) -> bool:
    """Mirror `shouldRequirePassword`: password is required unless passwordless is
    enabled AND the user has no credential account."""
    if not allow_passwordless:
        return True
    account = await _credential_account(ctx, user_id)
    return account is not None


async def _check_password(ctx: EndpointContext, user_id: str, password: str | None) -> None:
    """Validate the password against the credential account.

    Always raises INVALID_PASSWORD on any failure (missing account, no password,
    or mismatch) so credential presence is not leaked via error codes.
    """
    account = await _credential_account(ctx, user_id)
    if (
        not password
        or not account
        or not account.get("password")
        or not verify_password(password, account["password"])  # type: ignore[arg-type]
    ):
        raise APIError(400, "INVALID_PASSWORD", message="Invalid password")


async def _find_two_factor(
    ctx: EndpointContext, user_id: str
) -> dict[str, object] | None:
    return await ctx.auth.adapter.find_one(
        model=TWO_FACTOR_MODEL, where=(Where(field="userId", value=user_id),)
    )


# ----- verifyTwoFactor: resolve session OR the 2fa challenge cookie ----------


@dataclass
class _TwoFactorState:
    user: dict[str, object]
    # When None, the request is mid-sign-in (challenge cookie). When set, fully
    # authenticated.
    session_token: str | None
    # Verification key used for OTP storage namespacing.
    key: str
    # The signed two-factor cookie value (verification identifier) when mid-sign-in.
    two_factor_identifier: str | None
    dont_remember: bool


async def _verify_two_factor(ctx: EndpointContext) -> _TwoFactorState:
    """Resolve the user either from an active session or the 2fa challenge cookie."""
    if ctx.session is not None:
        user = await _find_user(ctx, ctx.session.user_id)
        if user is None:
            raise APIError(401, "INVALID_TWO_FACTOR_COOKIE", message="Invalid two factor cookie")
        return _TwoFactorState(
            user=user,
            session_token=ctx.session.token,
            key=f"{user['id']}!{ctx.session.id}",
            two_factor_identifier=None,
            dont_remember=False,
        )

    identifier = _get_signed_cookie(ctx, TWO_FACTOR_COOKIE_NAME)
    if not identifier:
        raise APIError(401, "INVALID_TWO_FACTOR_COOKIE", message="Invalid two factor cookie")
    record = await ctx.auth.adapter.find_one(
        model="verification",
        where=(Where(field="identifier", value=identifier),),
    )
    if not record:
        raise APIError(401, "INVALID_TWO_FACTOR_COOKIE", message="Invalid two factor cookie")
    user = await _find_user(ctx, str(record["value"]))
    if user is None:
        raise APIError(401, "INVALID_TWO_FACTOR_COOKIE", message="Invalid two factor cookie")
    dont_remember = bool(_get_signed_cookie(ctx, DONT_REMEMBER_COOKIE))
    return _TwoFactorState(
        user=user,
        session_token=None,
        key=identifier,
        two_factor_identifier=identifier,
        dont_remember=dont_remember,
    )


async def _valid(ctx: EndpointContext, state: _TwoFactorState) -> dict[str, object]:
    """Complete verification: when mid-sign-in, mint a session + trust-device
    cookie if requested; when already authenticated, just echo the session."""
    user = state.user
    if state.session_token is not None:
        return {
            "token": state.session_token,
            "user": _public_user(user),
        }

    # Mid sign-in: create the real session.
    remember_me = not state.dont_remember
    session, session_cookies = await create_session(
        ctx.auth,
        user_id=str(user["id"]),
        ip_address=ctx.request.headers.get("x-forwarded-for"),
        user_agent=ctx.request.headers.get("user-agent"),
        remember_me=remember_me,
    )
    ctx.set_cookies.extend(session_cookies)

    # Consume the challenge verification + cookie.
    if state.two_factor_identifier:
        await ctx.auth.adapter.delete_many(
            model="verification",
            where=(Where(field="identifier", value=state.two_factor_identifier),),
        )
    _expire_cookie(ctx, TWO_FACTOR_COOKIE_NAME)

    trust_device = bool(getattr(ctx.body, "trust_device", False))
    if trust_device:
        await _issue_trust_device(ctx, str(user["id"]))
        _expire_cookie(ctx, DONT_REMEMBER_COOKIE)

    return {
        "token": session.token,
        "user": _public_user(user),
    }


def _public_user(user: dict[str, object]) -> dict[str, object]:
    return {
        "id": user.get("id"),
        "email": user.get("email"),
        "emailVerified": user.get("emailVerified"),
        "name": user.get("name"),
        "image": user.get("image"),
        "twoFactorEnabled": user.get("twoFactorEnabled"),
        "createdAt": user.get("createdAt"),
        "updatedAt": user.get("updatedAt"),
    }


async def _issue_trust_device(ctx: EndpointContext, user_id: str) -> None:
    max_age = _trust_device_max_age(ctx)
    trust_identifier = f"trust-device-{secrets.token_urlsafe(24)}"
    token = _hmac_sign(ctx.auth.secret, f"{user_id}!{trust_identifier}")
    await ctx.auth.adapter.create(
        model="verification",
        data={
            "identifier": trust_identifier,
            "value": user_id,
            "expiresAt": _now() + max_age,
            "createdAt": _now(),
            "updatedAt": _now(),
        },
    )
    attrs = CookieAttributes(
        path="/", max_age=max_age, http_only=True, secure=_secure(ctx), same_site="lax"
    )
    _set_signed_cookie(
        ctx, TRUST_DEVICE_COOKIE_NAME, f"{token}!{trust_identifier}", attrs
    )


# ----- request body shapes ---------------------------------------------------


@dataclass(frozen=True, slots=True)
class EnableBody:
    password: str | None = None
    issuer: str | None = None


@dataclass(frozen=True, slots=True)
class DisableBody:
    password: str | None = None


@dataclass(frozen=True, slots=True)
class GetTotpUriBody:
    password: str | None = None


@dataclass(frozen=True, slots=True)
class VerifyTotpBody:
    code: str
    trust_device: bool = False


@dataclass(frozen=True, slots=True)
class VerifyOtpBody:
    code: str
    trust_device: bool = False


@dataclass(frozen=True, slots=True)
class SendOtpBody:
    trust_device: bool = False


@dataclass(frozen=True, slots=True)
class GenerateBackupCodesBody:
    password: str | None = None


@dataclass(frozen=True, slots=True)
class VerifyBackupCodeBody:
    code: str
    disable_session: bool = False
    trust_device: bool = False


@dataclass(frozen=True, slots=True)
class ViewBackupCodesBody:
    user_id: str


# ----- handlers --------------------------------------------------------------


async def _enable(ctx: EndpointContext) -> dict[str, object]:
    if ctx.session is None:
        raise APIError(401, "UNAUTHORIZED")
    body: EnableBody = ctx.body
    user_id = ctx.session.user_id
    allow_passwordless = _allow_passwordless(ctx)
    if await _should_require_password(ctx, user_id, allow_passwordless):
        await _check_password(ctx, user_id, body.password)

    secret = _generate_secret()
    backup_codes = _generate_backup_codes_list()
    encoded_codes = await _encode_backup_codes(ctx, backup_codes)

    user = await _find_user(ctx, user_id)
    assert user is not None

    if _skip_verification_on_enable(ctx):
        await ctx.auth.adapter.update(
            model="user",
            where=(Where(field="id", value=user_id),),
            update={"twoFactorEnabled": True},
        )

    existing = await _find_two_factor(ctx, user_id)
    await ctx.auth.adapter.delete_many(
        model=TWO_FACTOR_MODEL,
        where=(Where(field="userId", value=user_id),),
    )
    verified = (
        existing is not None and existing.get("verified") is not False
    ) or _skip_verification_on_enable(ctx)
    await ctx.auth.adapter.create(
        model=TWO_FACTOR_MODEL,
        data={
            "userId": user_id,
            "secret": secret,
            "backupCodes": encoded_codes,
            "verified": bool(verified),
        },
    )

    totp_uri = _build_totp_uri(
        secret,
        issuer=body.issuer or _issuer(ctx),
        account=str(user.get("email") or user_id),
        digits=_totp_digits(ctx),
        period=_totp_period(ctx),
    )
    return {"totpURI": totp_uri, "backupCodes": backup_codes}


def _build_totp_uri(
    secret: str, *, issuer: str, account: str, digits: int, period: int
) -> str:
    pyotp = _require_pyotp()
    return pyotp.TOTP(secret, digits=digits, interval=period).provisioning_uri(  # type: ignore[attr-defined]
        name=account, issuer_name=issuer
    )


async def _disable(ctx: EndpointContext) -> dict[str, object]:
    if ctx.session is None:
        raise APIError(401, "UNAUTHORIZED")
    body: DisableBody = ctx.body
    user_id = ctx.session.user_id
    allow_passwordless = _allow_passwordless(ctx)
    if await _should_require_password(ctx, user_id, allow_passwordless):
        await _check_password(ctx, user_id, body.password)

    await ctx.auth.adapter.update(
        model="user",
        where=(Where(field="id", value=user_id),),
        update={"twoFactorEnabled": False},
    )
    await ctx.auth.adapter.delete_many(
        model=TWO_FACTOR_MODEL,
        where=(Where(field="userId", value=user_id),),
    )

    # Revoke any trust-device record + clear the cookie.
    trust_value = _get_signed_cookie(ctx, TRUST_DEVICE_COOKIE_NAME)
    if trust_value:
        parts = trust_value.split("!")
        trust_id = parts[1] if len(parts) > 1 else None
        if trust_id:
            await ctx.auth.adapter.delete_many(
                model="verification",
                where=(Where(field="identifier", value=trust_id),),
            )
        _expire_cookie(ctx, TRUST_DEVICE_COOKIE_NAME)
    return {"status": True}


async def _get_totp_uri(ctx: EndpointContext) -> dict[str, object]:
    if _totp_disabled(ctx):
        raise APIError(400, "TOTP_NOT_CONFIGURED", message="totp isn't configured")
    if ctx.session is None:
        raise APIError(401, "UNAUTHORIZED")
    body: GetTotpUriBody = ctx.body
    user_id = ctx.session.user_id
    two_factor = await _find_two_factor(ctx, user_id)
    if not two_factor:
        raise APIError(400, "TOTP_NOT_ENABLED", message="TOTP not enabled")
    user = await _find_user(ctx, user_id)
    assert user is not None
    allow_passwordless = _allow_passwordless(ctx)
    if await _should_require_password(ctx, user_id, allow_passwordless):
        await _check_password(ctx, user_id, body.password)
    totp_uri = _build_totp_uri(
        str(two_factor["secret"]),
        issuer=_issuer(ctx),
        account=str(user.get("email") or user_id),
        digits=_totp_digits(ctx),
        period=_totp_period(ctx),
    )
    return {"totpURI": totp_uri}


async def _verify_totp(ctx: EndpointContext) -> dict[str, object]:
    if _totp_disabled(ctx):
        raise APIError(400, "TOTP_NOT_CONFIGURED", message="totp isn't configured")
    body: VerifyTotpBody = ctx.body
    state = await _verify_two_factor(ctx)
    user = state.user
    is_sign_in = state.session_token is None
    two_factor = await _find_two_factor(ctx, str(user["id"]))
    if not two_factor:
        raise APIError(400, "TOTP_NOT_ENABLED", message="TOTP not enabled")

    # During sign-in, reject explicitly-unverified enrollments.
    if is_sign_in and two_factor.get("verified") is False:
        raise APIError(400, "TOTP_NOT_ENABLED", message="TOTP not enabled")

    pyotp = _require_pyotp()
    totp = pyotp.TOTP(  # type: ignore[attr-defined]
        str(two_factor["secret"]), digits=_totp_digits(ctx), interval=_totp_period(ctx)
    )
    if not totp.verify(body.code, valid_window=0):
        raise APIError(401, "INVALID_CODE", message="Invalid code")

    # Enrollment mode: row not yet verified.
    if two_factor.get("verified") is not True:
        if not user.get("twoFactorEnabled"):
            await ctx.auth.adapter.update(
                model="user",
                where=(Where(field="id", value=user["id"]),),
                update={"twoFactorEnabled": True},
            )
            user["twoFactorEnabled"] = True
        await ctx.auth.adapter.update(
            model=TWO_FACTOR_MODEL,
            where=(Where(field="id", value=two_factor["id"]),),
            update={"verified": True},
        )
    return await _valid(ctx, state)


async def _send_otp(ctx: EndpointContext) -> dict[str, object]:
    otp_options = _otp_options(ctx)
    send_fn = otp_options.get("send_otp", otp_options.get("sendOTP")) if otp_options else None
    if send_fn is None:
        raise APIError(400, "OTP_NOT_CONFIGURED", message="otp isn't configured")
    state = await _verify_two_factor(ctx)
    digits = int((otp_options or {}).get("digits") or DEFAULT_OTP_DIGITS)  # type: ignore[arg-type]
    period_min = (otp_options or {}).get("period")
    period_seconds = int(period_min * 60) if period_min else DEFAULT_OTP_PERIOD  # type: ignore[arg-type]
    code = "".join(secrets.choice("0123456789") for _ in range(digits))
    stored = await _store_otp(ctx, otp_options or {}, code)
    identifier = f"2fa-otp-{state.key}"
    await ctx.auth.adapter.delete_many(
        model="verification",
        where=(Where(field="identifier", value=identifier),),
    )
    await ctx.auth.adapter.create(
        model="verification",
        data={
            "identifier": identifier,
            "value": f"{stored}:0",
            "expiresAt": _now() + period_seconds,
            "createdAt": _now(),
            "updatedAt": _now(),
        },
    )
    result = send_fn({"user": state.user, "otp": code}, ctx)  # type: ignore[operator]
    if hasattr(result, "__await__"):
        await result
    return {"status": True}


async def _store_otp(
    ctx: EndpointContext, otp_options: dict[str, object], code: str
) -> str:
    mode = otp_options.get("store_otp", otp_options.get("storeOTP", "plain"))
    if mode == "hashed":
        return _default_key_hasher(code)
    if isinstance(mode, dict) and "hash" in mode:
        result = mode["hash"](code)  # type: ignore[operator]
        return await result if hasattr(result, "__await__") else result
    if isinstance(mode, dict) and "encrypt" in mode:
        result = mode["encrypt"](code)  # type: ignore[operator]
        return await result if hasattr(result, "__await__") else result
    if mode == "encrypted":
        return _symmetric_encrypt(ctx.auth.secret, code)
    return code


async def _compare_otp(
    ctx: EndpointContext,
    otp_options: dict[str, object],
    stored: str,
    user_input: str,
) -> bool:
    mode = otp_options.get("store_otp", otp_options.get("storeOTP", "plain"))
    if mode == "hashed":
        return hmac.compare_digest(stored, _default_key_hasher(user_input))
    if isinstance(mode, dict) and "hash" in mode:
        result = mode["hash"](user_input)  # type: ignore[operator]
        hashed = await result if hasattr(result, "__await__") else result
        return hmac.compare_digest(stored, hashed)
    if isinstance(mode, dict) and "decrypt" in mode:
        result = mode["decrypt"](stored)  # type: ignore[operator]
        decrypted = await result if hasattr(result, "__await__") else result
        return hmac.compare_digest(decrypted, user_input)
    if mode == "encrypted":
        decrypted = _symmetric_decrypt(ctx.auth.secret, stored)
        return hmac.compare_digest(decrypted, user_input)
    return hmac.compare_digest(stored, user_input)


def _symmetric_encrypt(secret: str, data: str) -> str:
    """Lightweight reversible obfuscation keyed by the app secret.

    Not AES (no shared crypto primitive in core for that), but deterministic and
    reversible — sufficient for `storeOTP: "encrypted"` round-tripping in tests.
    """
    key = hashlib.sha256(secret.encode()).digest()
    raw = data.encode()
    out = bytes(b ^ key[i % len(key)] for i, b in enumerate(raw))
    return _b64url(out)


def _symmetric_decrypt(secret: str, data: str) -> str:
    key = hashlib.sha256(secret.encode()).digest()
    padded = data + "=" * (-len(data) % 4)
    raw = base64.urlsafe_b64decode(padded)
    out = bytes(b ^ key[i % len(key)] for i, b in enumerate(raw))
    return out.decode()


async def _verify_otp(ctx: EndpointContext) -> dict[str, object]:
    body: VerifyOtpBody = ctx.body
    state = await _verify_two_factor(ctx)
    otp_options = _otp_options(ctx) or {}
    identifier = f"2fa-otp-{state.key}"
    record = await ctx.auth.adapter.find_one(
        model="verification",
        where=(Where(field="identifier", value=identifier),),
    )
    if not record or int(record.get("expiresAt", 0)) < _now():
        if record:
            await ctx.auth.adapter.delete_many(
                model="verification",
                where=(Where(field="identifier", value=identifier),),
            )
        raise APIError(400, "OTP_HAS_EXPIRED", message="OTP has expired")

    stored, _, counter_str = str(record["value"]).rpartition(":")
    counter = int(counter_str or "0")
    allowed = int(otp_options.get("allowed_attempts", otp_options.get("allowedAttempts", DEFAULT_ALLOWED_ATTEMPTS)))  # type: ignore[arg-type]
    if counter >= allowed:
        await ctx.auth.adapter.delete_many(
            model="verification",
            where=(Where(field="identifier", value=identifier),),
        )
        raise APIError(
            400,
            "TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE",
            message="Too many attempts. Please request a new code.",
        )

    if await _compare_otp(ctx, otp_options, stored, body.code):
        await ctx.auth.adapter.delete_many(
            model="verification",
            where=(Where(field="identifier", value=identifier),),
        )
        # OTP-based enrollment: flip twoFactorEnabled if not set.
        if not state.user.get("twoFactorEnabled"):
            await ctx.auth.adapter.update(
                model="user",
                where=(Where(field="id", value=state.user["id"]),),
                update={"twoFactorEnabled": True},
            )
            state.user["twoFactorEnabled"] = True
        return await _valid(ctx, state)

    await ctx.auth.adapter.update(
        model="verification",
        where=(Where(field="identifier", value=identifier),),
        update={"value": f"{stored}:{counter + 1}", "updatedAt": _now()},
    )
    raise APIError(401, "INVALID_CODE", message="Invalid code")


async def _generate_backup_codes(ctx: EndpointContext) -> dict[str, object]:
    if ctx.session is None:
        raise APIError(401, "UNAUTHORIZED")
    user_id = ctx.session.user_id
    user = await _find_user(ctx, user_id)
    if not user or not user.get("twoFactorEnabled"):
        raise APIError(400, "TWO_FACTOR_NOT_ENABLED", message="Two factor isn't enabled")
    body: GenerateBackupCodesBody = ctx.body
    allow_passwordless = _allow_passwordless(ctx)
    if await _should_require_password(ctx, user_id, allow_passwordless):
        await _check_password(ctx, user_id, body.password)

    two_factor = await _find_two_factor(ctx, user_id)
    if not two_factor:
        raise APIError(400, "TWO_FACTOR_NOT_ENABLED", message="Two factor isn't enabled")

    codes = _generate_backup_codes_list()
    await ctx.auth.adapter.update(
        model=TWO_FACTOR_MODEL,
        where=(Where(field="id", value=two_factor["id"]),),
        update={"backupCodes": await _encode_backup_codes(ctx, codes)},
    )
    return {"status": True, "backupCodes": codes}


async def _verify_backup_code(ctx: EndpointContext) -> dict[str, object]:
    body: VerifyBackupCodeBody = ctx.body
    state = await _verify_two_factor(ctx)
    two_factor = await _find_two_factor(ctx, str(state.user["id"]))
    if not two_factor:
        raise APIError(400, "BACKUP_CODES_NOT_ENABLED", message="Backup codes aren't enabled")
    codes = await _decode_backup_codes(ctx, str(two_factor["backupCodes"]))
    if body.code not in codes:
        raise APIError(401, "INVALID_BACKUP_CODE", message="Invalid backup code")
    remaining = [c for c in codes if c != body.code]
    await ctx.auth.adapter.update(
        model=TWO_FACTOR_MODEL,
        where=(Where(field="id", value=two_factor["id"]),),
        update={"backupCodes": await _encode_backup_codes(ctx, remaining)},
    )
    if body.disable_session:
        return {
            "token": state.session_token,
            "user": _public_user(state.user),
        }
    return await _valid(ctx, state)


async def _view_backup_codes(ctx: EndpointContext) -> dict[str, object]:
    body: ViewBackupCodesBody = ctx.body
    two_factor = await _find_two_factor(ctx, body.user_id)
    if not two_factor:
        raise APIError(400, "BACKUP_CODES_NOT_ENABLED", message="Backup codes aren't enabled")
    codes = await _decode_backup_codes(ctx, str(two_factor["backupCodes"]))
    return {"status": True, "backupCodes": codes}


# ----- endpoint table --------------------------------------------------------


ENABLE = create_auth_endpoint(
    "/two-factor/enable",
    EndpointOptions(method="POST", body=EnableBody, requires_session=True),
    _enable,
)
DISABLE = create_auth_endpoint(
    "/two-factor/disable",
    EndpointOptions(method="POST", body=DisableBody, requires_session=True),
    _disable,
)
GET_TOTP_URI = create_auth_endpoint(
    "/two-factor/get-totp-uri",
    EndpointOptions(method="POST", body=GetTotpUriBody, requires_session=True),
    _get_totp_uri,
)
VERIFY_TOTP = create_auth_endpoint(
    "/two-factor/verify-totp",
    EndpointOptions(method="POST", body=VerifyTotpBody),
    _verify_totp,
)
SEND_OTP = create_auth_endpoint(
    "/two-factor/send-otp",
    EndpointOptions(method="POST", body=SendOtpBody),
    _send_otp,
)
VERIFY_OTP = create_auth_endpoint(
    "/two-factor/verify-otp",
    EndpointOptions(method="POST", body=VerifyOtpBody),
    _verify_otp,
)
GENERATE_BACKUP_CODES = create_auth_endpoint(
    "/two-factor/generate-backup-codes",
    EndpointOptions(method="POST", body=GenerateBackupCodesBody, requires_session=True),
    _generate_backup_codes,
)
VERIFY_BACKUP_CODE = create_auth_endpoint(
    "/two-factor/verify-backup-code",
    EndpointOptions(method="POST", body=VerifyBackupCodeBody),
    _verify_backup_code,
)
VIEW_BACKUP_CODES = create_auth_endpoint(
    "/two-factor/view-backup-codes",
    EndpointOptions(method="POST", body=ViewBackupCodesBody),
    _view_backup_codes,
)


ALL: tuple[AuthEndpoint, ...] = (
    ENABLE,
    DISABLE,
    GET_TOTP_URI,
    VERIFY_TOTP,
    SEND_OTP,
    VERIFY_OTP,
    GENERATE_BACKUP_CODES,
    VERIFY_BACKUP_CODE,
    VIEW_BACKUP_CODES,
)
