"""two_factor plugin — TOTP + OTP + backup codes + trusted devices.

Port of `reference/packages/better-auth/src/plugins/two-factor/`.

Schema:
  * adds a `twoFactor` table (secret, backupCodes, verified, userId) — the
    upstream model.
  * extends `user` with `twoFactorEnabled`.

The challenge state between credential sign-in and the second factor travels
through signed cookies (`better-auth.two_factor`, `better-auth.trust_device`,
`better-auth.dont_remember`) plus rows on the core `verification` table.

Sign-in gating: an after-hook on `/sign-in/email`, `/sign-in/username`, and
`/sign-in/phone-number` inspects the freshly-minted session. When the user has
`twoFactorEnabled`, it deletes that session, clears its cookies, issues a signed
`two_factor` challenge cookie, and returns
`{twoFactorRedirect: True, twoFactorMethods: [...]}` instead of a full session.
A valid trust-device cookie short-circuits the gate (and is rotated).

Options are read from `BetterAuthOptions.advanced["two-factor"]`:

    advanced={
        "two-factor": {
            "otp_options": {"send_otp": async (data, ctx) -> None, ...},
            "skip_verification_on_enable": False,
            "allow_passwordless": False,
            "trust_device_max_age": 30*24*60*60,
            "two_factor_cookie_max_age": 600,
            "issuer": "My App",
            "totp_options": {"digits": 6, "period": 30, "disable": False},
        }
    }

Requires `pyotp` (declared under the `two-factor` extra of `better-auth`).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

from kernia.plugins.two_factor import routes
from kernia.types.adapter import FieldDef, ModelDef, Where
from kernia.types.context import EndpointContext
from kernia.types.endpoint import AuthEndpoint
from kernia.types.hooks import AfterHook, PluginHooks
from kernia.types.plugin import KerniaPlugin, PluginSchema, RateLimitRule

# Error codes: upstream set (camel-keyed) plus the legacy keys this port shipped
# with, so existing callers/tests keep working.
TWO_FACTOR_ERROR_CODES: Mapping[str, str] = {
    "OTP_NOT_ENABLED": "OTP not enabled",
    "OTP_HAS_EXPIRED": "OTP has expired",
    "TOTP_NOT_ENABLED": "TOTP not enabled",
    "TWO_FACTOR_NOT_ENABLED": "Two factor isn't enabled",
    "BACKUP_CODES_NOT_ENABLED": "Backup codes aren't enabled",
    "INVALID_BACKUP_CODE": "Invalid backup code",
    "INVALID_CODE": "Invalid code",
    "TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE": "Too many attempts. Please request a new code.",
    "INVALID_TWO_FACTOR_COOKIE": "Invalid two factor cookie",
    # legacy keys (kept for backward compatibility)
    "INVALID_TWO_FACTOR_CODE": "Two-factor code is invalid.",
    "INVALID_TWO_FACTOR_CONFIRMATION": "Two-factor confirmation is invalid or expired.",
}


_TWO_FACTOR_USER_FIELDS: tuple[FieldDef, ...] = (
    FieldDef("twoFactorEnabled", "boolean", required=False, default=False, input=False),
    # Retained from the previous design for backward compatibility (unused by the
    # new code path, which stores the secret on the twoFactor table).
    FieldDef("twoFactorSecret", "string", required=False),
)

# Upstream model: the source of truth for secret + backup codes.
_TWO_FACTOR_MODEL = ModelDef(
    name="twoFactor",
    fields=(
        FieldDef("id", "string", unique=True),
        FieldDef("userId", "string", references=("user", "id"), index=True),
        FieldDef("secret", "string", returned=False, index=True),
        FieldDef("backupCodes", "string", returned=False),
        FieldDef("verified", "boolean", required=False, default=True, input=False),
    ),
)

# Legacy tables retained so prior callers/migrations don't break.
_TWO_FACTOR_CONFIRMATION_MODEL = ModelDef(
    name="twoFactorConfirmation",
    fields=(
        FieldDef("id", "string", unique=True),
        FieldDef("userId", "string", references=("user", "id")),
        FieldDef("expiresAt", "date"),
        FieldDef("createdAt", "date"),
    ),
)
_TWO_FACTOR_BACKUP_CODE_MODEL = ModelDef(
    name="twoFactorBackupCode",
    fields=(
        FieldDef("id", "string", unique=True),
        FieldDef("userId", "string", references=("user", "id")),
        FieldDef("codeHash", "string"),
        FieldDef("used", "boolean", default=False),
        FieldDef("createdAt", "date"),
    ),
)


_SIGN_IN_PATHS = {"/sign-in/email", "/sign-in/username", "/sign-in/phone-number"}


def _sign_in_matcher(ctx: EndpointContext) -> bool:
    return ctx.request.path in _SIGN_IN_PATHS


def _opts(ctx: EndpointContext) -> dict[str, object]:
    return dict(ctx.auth.options.advanced.get(routes.OPTIONS_KEY) or {})


async def _try_trust_device(ctx: EndpointContext, user_id: str) -> bool:
    """If a valid trust-device cookie is present, rotate it and return True so the
    sign-in proceeds without a 2FA challenge. Otherwise clear it and return False.
    """
    raw = ctx.request.cookies.get(routes.TRUST_DEVICE_COOKIE_NAME)
    if not raw:
        return False
    value = verify(raw, secret=ctx.auth.secret)
    if not value or "!" not in value:
        return False
    token, trust_identifier = value.split("!", 1)
    expected = routes._hmac_sign(ctx.auth.secret, f"{user_id}!{trust_identifier}")
    if token != expected:
        routes._expire_cookie(ctx, routes.TRUST_DEVICE_COOKIE_NAME)
        return False
    record = await ctx.auth.adapter.find_one(
        model="verification",
        where=(Where(field="identifier", value=trust_identifier),),
    )
    if (
        not record
        or str(record.get("value")) != user_id
        or int(record.get("expiresAt", 0)) <= routes._now()
    ):
        routes._expire_cookie(ctx, routes.TRUST_DEVICE_COOKIE_NAME)
        return False
    # Valid — rotate the server-side record + cookie.
    await ctx.auth.adapter.delete_many(
        model="verification",
        where=(Where(field="identifier", value=trust_identifier),),
    )
    await routes._issue_trust_device(ctx, user_id)
    return True


async def _two_factor_methods(ctx: EndpointContext, user_id: str) -> list[str]:
    methods: list[str] = []
    opts = _opts(ctx)
    totp_options = dict(opts.get("totp_options", opts.get("totpOptions")) or {})
    if not totp_options.get("disable"):
        two_factor = await ctx.auth.adapter.find_one(
            model=routes.TWO_FACTOR_MODEL,
            where=(Where(field="userId", value=user_id),),
        )
        if two_factor and two_factor.get("verified") is not False:
            methods.append("totp")
    otp_options = opts.get("otp_options", opts.get("otpOptions")) or {}
    if isinstance(otp_options, dict) and (
        otp_options.get("send_otp") or otp_options.get("sendOTP")
    ):
        methods.append("otp")
    return methods


async def _intercept_sign_in(ctx: EndpointContext, result: object) -> object | None:
    """Convert a credential sign-in into a 2FA challenge when 2FA is enabled."""
    if not isinstance(result, dict):
        return None
    user_obj = result.get("user")
    if not isinstance(user_obj, dict):
        return None
    user_id = user_obj.get("id")
    if not user_id:
        return None
    user = await ctx.auth.adapter.find_one(
        model="user", where=(Where(field="id", value=user_id),)
    )
    if not user or not user.get("twoFactorEnabled"):
        return None

    session_info = result.get("session")

    # Trust-device fast path: skip the challenge and keep the just-minted session.
    if await _try_trust_device(ctx, str(user_id)):
        return result

    # Tear down the session that the sign-in handler created.
    if isinstance(session_info, dict) and session_info.get("id"):
        await ctx.auth.adapter.delete_many(
            model="session",
            where=(Where(field="id", value=session_info["id"]),),
        )
    # Drop the session cookies the sign-in handler queued.
    ctx.set_cookies[:] = [
        c
        for c in ctx.set_cookies
        if c[0] not in (SESSION_TOKEN_COOKIE, SESSION_DATA_COOKIE)
    ]

    max_age = routes._two_factor_cookie_max_age(ctx)
    secure = ctx.auth.base_url.startswith("https")

    # Persist the challenge state on the verification table, keyed by the cookie.
    identifier = f"2fa-{routes.secrets.token_urlsafe(15)}"
    now = routes._now()
    await ctx.auth.adapter.create(
        model="verification",
        data={
            "identifier": identifier,
            "value": str(user_id),
            "expiresAt": now + max_age,
            "createdAt": now,
            "updatedAt": now,
        },
    )
    attrs = CookieAttributes(
        path="/", max_age=max_age, http_only=True, secure=secure, same_site="lax"
    )
    ctx.set_cookies.append(
        (routes.TWO_FACTOR_COOKIE_NAME, sign(identifier, secret=ctx.auth.secret), attrs)
    )
    # dont_remember cookie mirrors upstream: present so verify-otp can read it.
    ctx.set_cookies.append(
        (
            DONT_REMEMBER_COOKIE,
            sign("true", secret=ctx.auth.secret),
            CookieAttributes(path="/", max_age=max_age, http_only=True, secure=secure, same_site="lax"),
        )
    )

    methods = await _two_factor_methods(ctx, str(user_id))
    return {"twoFactorRedirect": True, "twoFactorMethods": methods}


@dataclass(frozen=True, slots=True)
class _TwoFactorPlugin:
    id: str = "two-factor"
    version: str | None = None
    schema: PluginSchema | None = field(
        default_factory=lambda: PluginSchema(
            tables=(
                _TWO_FACTOR_MODEL,
                _TWO_FACTOR_CONFIRMATION_MODEL,
                _TWO_FACTOR_BACKUP_CODE_MODEL,
            ),
            extend={"user": _TWO_FACTOR_USER_FIELDS},
        )
    )
    endpoints: tuple[AuthEndpoint, ...] = field(default_factory=lambda: routes.ALL)
    middlewares: None = None
    hooks: PluginHooks | None = field(
        default_factory=lambda: PluginHooks(
            after=(AfterHook(match=_sign_in_matcher, handler=_intercept_sign_in),),
        )
    )
    on_request: None = None
    on_response: None = None
    rate_limit: tuple[RateLimitRule, ...] = (
        RateLimitRule(path="/two-factor/verify-totp", window=60, max=10),
        RateLimitRule(path="/two-factor/verify-otp", window=60, max=10),
        RateLimitRule(path="/two-factor/verify-backup-code", window=60, max=5),
        RateLimitRule(path="/two-factor/send-otp", window=60, max=3),
    )
    error_codes: Mapping[str, str] = field(
        default_factory=lambda: dict(TWO_FACTOR_ERROR_CODES)
    )
    init: None = None


def two_factor() -> KerniaPlugin:
    """Construct the two-factor plugin."""
    return _TwoFactorPlugin()  # type: ignore[return-value]


__all__ = ["TWO_FACTOR_ERROR_CODES", "two_factor"]
