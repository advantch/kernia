"""Admin plugin construction.

Routes live in `routes.py`; this file wires the plugin metadata, schema
extension, hooks (ban enforcement on the active session + banned sign-in
rejection), error codes, and option normalisation.

Mirrors `reference/packages/better-auth/src/plugins/admin/admin.ts`.
"""

from __future__ import annotations

import time as _time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from kernia.error import APIError
from kernia.plugins.access import Role, default_roles
from kernia.plugins.admin import routes
from kernia.types.adapter import FieldDef, Where
from kernia.types.endpoint import AuthEndpoint
from kernia.types.hooks import BeforeHook, PluginHooks
from kernia.types.plugin import KerniaPlugin, PluginSchema, RateLimitRule

ADMIN_ERROR_CODES: Mapping[str, str] = {
    "FAILED_TO_CREATE_USER": "Failed to create user",
    "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL": "User already exists. Use another email.",
    "YOU_CANNOT_BAN_YOURSELF": "You cannot ban yourself",
    "YOU_ARE_NOT_ALLOWED_TO_CHANGE_USERS_ROLE": "You are not allowed to change users role",
    "YOU_ARE_NOT_ALLOWED_TO_CREATE_USERS": "You are not allowed to create users",
    "YOU_ARE_NOT_ALLOWED_TO_LIST_USERS": "You are not allowed to list users",
    "YOU_ARE_NOT_ALLOWED_TO_LIST_USERS_SESSIONS": "You are not allowed to list users sessions",
    "YOU_ARE_NOT_ALLOWED_TO_BAN_USERS": "You are not allowed to ban users",
    "YOU_ARE_NOT_ALLOWED_TO_IMPERSONATE_USERS": "You are not allowed to impersonate users",
    "YOU_ARE_NOT_ALLOWED_TO_REVOKE_USERS_SESSIONS": "You are not allowed to revoke users sessions",
    "YOU_ARE_NOT_ALLOWED_TO_DELETE_USERS": "You are not allowed to delete users",
    "YOU_ARE_NOT_ALLOWED_TO_SET_USERS_PASSWORD": "You are not allowed to set users password",
    "BANNED_USER": "You have been banned from this application",
    "USER_BANNED": "You have been banned from this application",
    "YOU_ARE_NOT_ALLOWED_TO_GET_USER": "You are not allowed to get user",
    "NO_DATA_TO_UPDATE": "No data to update",
    "YOU_ARE_NOT_ALLOWED_TO_UPDATE_USERS": "You are not allowed to update users",
    "YOU_CANNOT_REMOVE_YOURSELF": "You cannot remove yourself",
    "YOU_ARE_NOT_ALLOWED_TO_SET_NON_EXISTENT_VALUE": (
        "You are not allowed to set a non-existent role value"
    ),
    "YOU_CANNOT_IMPERSONATE_ADMINS": "You cannot impersonate admins",
    "NOT_IMPERSONATING": "You are not currently impersonating a user.",
    "INVALID_ROLE_TYPE": "Invalid role type",
}


_ADMIN_FIELDS: tuple[FieldDef, ...] = (
    FieldDef("role", "string", required=False, default="user"),
    FieldDef("banned", "boolean", required=False, default=False),
    FieldDef("banReason", "string", required=False),
    FieldDef("banExpires", "number", required=False),
)

_SESSION_FIELDS: tuple[FieldDef, ...] = (FieldDef("impersonatedBy", "string", required=False),)


@dataclass(frozen=True, slots=True)
class AdminOptions:
    """Construction options. Mirrors `AdminOptions` in upstream `types.ts`.

    ``default_role``                 — role assigned to new users (default ``"user"``).
    ``admin_roles``                  — roles treated as admin for gating.
    ``admin_user_ids``               — user ids that are admins regardless of role.
    ``roles``                        — custom role map; falls back to ``default_roles()``.
    ``banned_user_message``          — message shown when a banned user is rejected.
    ``default_ban_reason``           — reason applied when ``banReason`` is omitted.
    ``default_ban_expires_in``       — default ban duration (seconds); ``None`` = never.
    ``impersonation_session_duration`` — impersonation session lifetime (seconds).
    ``allow_impersonating_admins``   — legacy escape hatch for impersonating admins.
    """

    default_role: str = "user"
    admin_roles: tuple[str, ...] = ("admin",)
    admin_user_ids: tuple[str, ...] = ()
    roles: Mapping[str, Role] | None = None
    banned_user_message: str = (
        "You have been banned from this application. Please contact support if you "
        "believe this is an error."
    )
    default_ban_reason: str | None = None
    default_ban_expires_in: int | None = None
    impersonation_session_duration: int | None = None
    allow_impersonating_admins: bool = False


@dataclass(frozen=True)
class _AdminPlugin:
    id: str = "admin"
    version: str | None = "0.0.0"
    schema: PluginSchema | None = None
    endpoints: Sequence[AuthEndpoint] = ()
    middlewares: None = None
    hooks: PluginHooks | None = None
    on_request: None = None
    on_response: None = None
    rate_limit: Sequence[RateLimitRule] | None = None
    error_codes: Mapping[str, str] = field(default_factory=lambda: dict(ADMIN_ERROR_CODES))
    init: None = None
    options: AdminOptions = field(default_factory=AdminOptions)


def admin(options: AdminOptions | None = None) -> KerniaPlugin:
    """Construct the admin plugin."""
    opts = options or AdminOptions()
    roles = dict(opts.roles) if opts.roles is not None else default_roles()

    # Validate that every declared admin role exists in the role map. Mirrors the
    # `BetterAuthError` raised by upstream `admin()` on unknown admin roles.
    lower_roles = {r.lower() for r in roles}
    unknown = [r for r in opts.admin_roles if r.lower() not in lower_roles]
    if unknown:
        raise ValueError(
            f"Invalid admin roles: {', '.join(unknown)}. "
            "Admin roles must be defined in the 'roles' configuration."
        )

    endpoints = routes.build_endpoints(opts, roles)

    # Ban enforcement on the *active* session (the cookie-resolved user). Mirrors
    # upstream's `session.create.before` ban check, applied here to every gated
    # request so a mid-session ban is honoured immediately.
    async def _ban_check(ctx: Any) -> None:
        if ctx.session is None:
            return
        user = await ctx.auth.adapter.find_one(
            model="user",
            where=(Where(field="id", value=ctx.session.user_id),),
        )
        if not user or not user.get("banned"):
            return
        expires = user.get("banExpires")
        if expires is not None and int(expires) < int(_time.time()):
            # Lapsed ban: auto-unban on access.
            await ctx.auth.adapter.update(
                model="user",
                where=(Where(field="id", value=user["id"]),),
                update={"banned": False, "banReason": None, "banExpires": None},
            )
            return
        raise APIError(403, "USER_BANNED", message=opts.banned_user_message)

    # Banned sign-in rejection. The session-create path bypasses database hooks in
    # this port, so we reject at the email/password sign-in boundary by looking up
    # the user named in the request body. Mirrors upstream `BANNED_USER` (403).
    async def _ban_signin_check(ctx: Any) -> None:
        body = ctx.body
        email = getattr(body, "email", None) if body is not None else None
        if not email:
            return
        user = await ctx.auth.adapter.find_one(
            model="user",
            where=(Where(field="email", value=email),),
        )
        if not user or not user.get("banned"):
            return
        expires = user.get("banExpires")
        if expires is not None and int(expires) < int(_time.time()):
            await ctx.auth.adapter.update(
                model="user",
                where=(Where(field="id", value=user["id"]),),
                update={"banned": False, "banReason": None, "banExpires": None},
            )
            return
        raise APIError(403, "BANNED_USER", message=opts.banned_user_message)

    hooks = PluginHooks(
        before=(
            BeforeHook(
                match=lambda ctx: (
                    ctx.request.path not in {"/sign-out", "/admin/stop-impersonating"}
                    and not ctx.request.path.startswith("/sign-in")
                    and not ctx.request.path.startswith("/sign-up")
                ),
                handler=_ban_check,
            ),
            BeforeHook(
                match=lambda ctx: ctx.request.path == "/sign-in/email",
                handler=_ban_signin_check,
            ),
        )
    )

    return _AdminPlugin(  # type: ignore[return-value]
        schema=PluginSchema(extend={"user": _ADMIN_FIELDS, "session": _SESSION_FIELDS}),
        endpoints=endpoints,
        hooks=hooks,
        options=opts,
    )
