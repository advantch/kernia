"""two_factor plugin — TOTP + backup codes.

Port of `reference/packages/better-auth/src/plugins/two-factor/`. Adds two tables
(`twoFactorConfirmation`, `twoFactorBackupCode`) and extends `user` with
`twoFactorEnabled` + `twoFactorSecret`.

Hooks into `/sign-in/email`: if the user has 2FA enabled, the endpoint normally
returns a session; the after-hook intercepts that, deletes the just-created
session, and returns `{requiresTwoFactor: True, confirmationId: ...}` instead.
The follow-up `/two-factor/verify-totp` (or `/two-factor/verify-backup-code`)
exchanges the confirmation id for a real session.

Requires `pyotp` (declared under the `two-factor` extra of `better-auth`).
"""

from __future__ import annotations

import secrets
import time
from collections.abc import Mapping
from dataclasses import dataclass, field

from better_auth.plugins.two_factor import routes
from better_auth.types.adapter import FieldDef, ModelDef, Where
from better_auth.types.context import EndpointContext
from better_auth.types.endpoint import AuthEndpoint
from better_auth.types.hooks import AfterHook, PluginHooks
from better_auth.types.plugin import BetterAuthPlugin, PluginSchema, RateLimitRule


TWO_FACTOR_ERROR_CODES: Mapping[str, str] = {
    "TWO_FACTOR_NOT_ENABLED": "Two-factor authentication is not enabled for this account.",
    "INVALID_TWO_FACTOR_CODE": "Two-factor code is invalid.",
    "INVALID_TWO_FACTOR_CONFIRMATION": "Two-factor confirmation is invalid or expired.",
    "INVALID_BACKUP_CODE": "Backup code is invalid or already used.",
}


_TWO_FACTOR_USER_FIELDS: tuple[FieldDef, ...] = (
    FieldDef("twoFactorEnabled", "boolean", required=False, default=False),
    FieldDef("twoFactorSecret", "string", required=False),
)

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


_SIGN_IN_PATHS = {"/sign-in/email", "/sign-in/username"}


def _sign_in_matcher(ctx: EndpointContext) -> bool:
    return ctx.request.path in _SIGN_IN_PATHS


async def _intercept_sign_in(
    ctx: EndpointContext, result: object
) -> object | None:
    """If the just-signed-in user has 2FA enabled, replace the session with a
    pending confirmation row and clear the session cookie."""
    if not isinstance(result, dict):
        return None
    user_obj = result.get("user")
    if not isinstance(user_obj, dict):
        return None
    user_id = user_obj.get("id")
    if not user_id:
        return None
    user = await ctx.auth.adapter.find_one(
        model="user",
        where=(Where(field="id", value=user_id),),
    )
    if not user or not user.get("twoFactorEnabled"):
        return None
    session_info = result.get("session")
    if isinstance(session_info, dict) and "id" in session_info:
        await ctx.auth.adapter.delete_many(
            model="session",
            where=(Where(field="id", value=session_info["id"]),),
        )
    ctx.set_cookies.clear()
    confirmation_id = secrets.token_urlsafe(24)
    now = int(time.time())
    await ctx.auth.adapter.create(
        model="twoFactorConfirmation",
        data={
            "id": confirmation_id,
            "userId": user_id,
            "expiresAt": now + routes.CONFIRMATION_TTL_SECONDS,
            "createdAt": now,
        },
    )
    return {"requiresTwoFactor": True, "confirmationId": confirmation_id}


@dataclass(frozen=True, slots=True)
class _TwoFactorPlugin:
    id: str = "two-factor"
    version: str | None = None
    schema: PluginSchema | None = field(
        default_factory=lambda: PluginSchema(
            tables=(_TWO_FACTOR_CONFIRMATION_MODEL, _TWO_FACTOR_BACKUP_CODE_MODEL),
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
        RateLimitRule(path="/two-factor/verify-backup-code", window=60, max=5),
    )
    error_codes: Mapping[str, str] = field(
        default_factory=lambda: dict(TWO_FACTOR_ERROR_CODES)
    )
    init: None = None


def two_factor() -> BetterAuthPlugin:
    """Construct the two-factor plugin."""
    return _TwoFactorPlugin()  # type: ignore[return-value]


__all__ = ["TWO_FACTOR_ERROR_CODES", "two_factor"]
