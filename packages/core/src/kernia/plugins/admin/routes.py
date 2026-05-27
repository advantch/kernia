"""Admin endpoint handlers.

Mirrors `reference/packages/better-auth/src/plugins/admin/routes.ts` to the
extent we need for parity. Endpoint construction happens at plugin-build time
in `plugin.py`; this module provides the handlers + a `build_endpoints(opts)`
factory.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from kernia.api.endpoint import create_auth_endpoint
from kernia.context import create_session, revoke_session
from kernia.cookies import sign
from kernia.crypto import hash_password
from kernia.error import APIError
from kernia.plugins.access import Role
from kernia.types.adapter import Where
from kernia.types.context import EndpointContext, Session
from kernia.types.cookie import (
    DONT_REMEMBER_COOKIE,
    SESSION_TOKEN_COOKIE,
    CookieAttributes,
)
from kernia.types.endpoint import AuthEndpoint, EndpointOptions

if TYPE_CHECKING:
    from kernia.plugins.admin.plugin import AdminOptions


ADMIN_IMPERSONATION_COOKIE = "better-auth.admin_session"


# ---------------------------------------------------------------------------
# Request body dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ListUsersBody:
    limit: int | None = None
    offset: int | None = None
    search_field: str | None = None
    search_value: str | None = None


@dataclass(frozen=True, slots=True)
class GetUserBody:
    user_id: str | None = None
    email: str | None = None


@dataclass(frozen=True, slots=True)
class CreateUserBody:
    email: str
    password: str
    name: str | None = None
    role: str = "user"


@dataclass(frozen=True, slots=True)
class UpdateUserBody:
    user_id: str
    name: str | None = None
    email: str | None = None
    image: str | None = None


@dataclass(frozen=True, slots=True)
class SetRoleBody:
    user_id: str
    role: str


@dataclass(frozen=True, slots=True)
class BanUserBody:
    user_id: str
    reason: str | None = None
    expires_in: int | None = None  # seconds from now


@dataclass(frozen=True, slots=True)
class UnbanUserBody:
    user_id: str


@dataclass(frozen=True, slots=True)
class ImpersonateBody:
    user_id: str


@dataclass(frozen=True, slots=True)
class ListUserSessionsBody:
    user_id: str


@dataclass(frozen=True, slots=True)
class RevokeUserSessionBody:
    session_id: str


@dataclass(frozen=True, slots=True)
class RevokeUserSessionsBody:
    user_id: str


@dataclass(frozen=True, slots=True)
class SetPasswordBody:
    user_id: str
    new_password: str


@dataclass(frozen=True, slots=True)
class RemoveUserBody:
    user_id: str


@dataclass(frozen=True, slots=True)
class HasPermissionBody:
    permissions: dict[str, Any]
    user_id: str | None = None


# ---------------------------------------------------------------------------
# Gating helpers
# ---------------------------------------------------------------------------


def _resolve_role(opts: AdminOptions, roles_map: dict[str, Role], user_row: dict | None) -> Role:
    if user_row is None:
        return roles_map.get(opts.default_role) or roles_map["user"]
    role_name = user_row.get("role") or opts.default_role
    # Multi-role users separated by comma; pick first matching for now.
    for r in str(role_name).split(","):
        r = r.strip()
        if r in roles_map:
            return roles_map[r]
    return roles_map.get(opts.default_role) or roles_map["user"]


def _is_admin(opts: AdminOptions, user_row: dict | None) -> bool:
    if user_row is None:
        return False
    if user_row["id"] in opts.admin_user_ids:
        return True
    role_name = user_row.get("role") or opts.default_role
    parts = [r.strip() for r in str(role_name).split(",")]
    return any(r in opts.admin_roles for r in parts)


async def _require_admin(
    ctx: EndpointContext,
    opts: AdminOptions,
    roles_map: dict[str, Role],
    *,
    error_code: str,
) -> dict:
    if ctx.session is None:
        raise APIError(401, "UNAUTHORIZED")
    user = await ctx.auth.adapter.find_one(
        model="user",
        where=(Where(field="id", value=ctx.session.user_id),),
    )
    if not _is_admin(opts, user):
        raise APIError(403, error_code)
    return user  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# Handler factory — closes over opts + roles_map
# ---------------------------------------------------------------------------


def build_endpoints(opts: AdminOptions, roles_map: dict[str, Role]) -> tuple[AuthEndpoint, ...]:
    async def list_users(ctx: EndpointContext) -> dict[str, Any]:
        await _require_admin(ctx, opts, roles_map, error_code="YOU_ARE_NOT_ALLOWED_TO_LIST_USERS")
        body: ListUsersBody = ctx.body or ListUsersBody()
        where: tuple[Where, ...] = ()
        if body.search_field and body.search_value:
            where = (Where(field=body.search_field, value=body.search_value, operator="contains"),)
        rows = await ctx.auth.adapter.find_many(
            model="user",
            where=where,
            limit=body.limit,
            offset=body.offset,
        )
        total = await ctx.auth.adapter.count(model="user", where=where)
        return {"users": rows, "total": total}

    async def get_user(ctx: EndpointContext) -> dict[str, Any]:
        await _require_admin(ctx, opts, roles_map, error_code="YOU_ARE_NOT_ALLOWED_TO_GET_USER")
        body: GetUserBody = ctx.body
        if body.user_id:
            where = (Where(field="id", value=body.user_id),)
        elif body.email:
            where = (Where(field="email", value=body.email),)
        else:
            raise APIError(400, "INVALID_REQUEST", message="user_id or email required")
        user = await ctx.auth.adapter.find_one(model="user", where=where)
        if not user:
            raise APIError(404, "USER_NOT_FOUND")
        return user

    async def create_user(ctx: EndpointContext) -> dict[str, Any]:
        await _require_admin(ctx, opts, roles_map, error_code="YOU_ARE_NOT_ALLOWED_TO_CREATE_USERS")
        body: CreateUserBody = ctx.body
        if body.role not in roles_map:
            raise APIError(400, "INVALID_ROLE_TYPE")
        existing = await ctx.auth.adapter.find_one(
            model="user",
            where=(Where(field="email", value=body.email),),
        )
        if existing:
            raise APIError(409, "USER_ALREADY_EXISTS")
        now = int(time.time())
        user = await ctx.auth.adapter.create(
            model="user",
            data={
                "email": body.email,
                "name": body.name,
                "emailVerified": False,
                "role": body.role,
                "banned": False,
                "createdAt": now,
                "updatedAt": now,
            },
        )
        await ctx.auth.adapter.create(
            model="account",
            data={
                "userId": user["id"],
                "accountId": user["id"],
                "providerId": "credential",
                "password": hash_password(body.password),
                "createdAt": now,
                "updatedAt": now,
            },
        )
        return {"user": user}

    async def update_user(ctx: EndpointContext) -> dict[str, Any]:
        await _require_admin(ctx, opts, roles_map, error_code="YOU_ARE_NOT_ALLOWED_TO_UPDATE_USERS")
        body: UpdateUserBody = ctx.body
        updates: dict[str, Any] = {}
        for f in ("name", "email", "image"):
            v = getattr(body, f)
            if v is not None:
                updates[f] = v
        if not updates:
            raise APIError(400, "INVALID_REQUEST", message="No fields to update")
        updates["updatedAt"] = int(time.time())
        user = await ctx.auth.adapter.update(
            model="user",
            where=(Where(field="id", value=body.user_id),),
            update=updates,
        )
        if not user:
            raise APIError(404, "USER_NOT_FOUND")
        return user

    async def set_role(ctx: EndpointContext) -> dict[str, Any]:
        await _require_admin(
            ctx, opts, roles_map, error_code="YOU_ARE_NOT_ALLOWED_TO_CHANGE_USERS_ROLE"
        )
        body: SetRoleBody = ctx.body
        if body.role not in roles_map:
            raise APIError(400, "INVALID_ROLE_TYPE")
        user = await ctx.auth.adapter.update(
            model="user",
            where=(Where(field="id", value=body.user_id),),
            update={"role": body.role, "updatedAt": int(time.time())},
        )
        if not user:
            raise APIError(404, "USER_NOT_FOUND")
        return user

    async def ban_user(ctx: EndpointContext) -> dict[str, Any]:
        caller = await _require_admin(
            ctx, opts, roles_map, error_code="YOU_ARE_NOT_ALLOWED_TO_BAN_USERS"
        )
        body: BanUserBody = ctx.body
        if body.user_id == caller["id"]:
            raise APIError(400, "YOU_CANNOT_BAN_YOURSELF")
        now = int(time.time())
        updates: dict[str, Any] = {
            "banned": True,
            "banReason": body.reason,
            "banExpires": (now + body.expires_in) if body.expires_in else None,
            "updatedAt": now,
        }
        user = await ctx.auth.adapter.update(
            model="user",
            where=(Where(field="id", value=body.user_id),),
            update=updates,
        )
        if not user:
            raise APIError(404, "USER_NOT_FOUND")
        # Revoke all sessions for the banned user.
        await ctx.auth.adapter.delete_many(
            model="session",
            where=(Where(field="userId", value=body.user_id),),
        )
        return {"user": user}

    async def unban_user(ctx: EndpointContext) -> dict[str, Any]:
        await _require_admin(ctx, opts, roles_map, error_code="YOU_ARE_NOT_ALLOWED_TO_BAN_USERS")
        body: UnbanUserBody = ctx.body
        user = await ctx.auth.adapter.update(
            model="user",
            where=(Where(field="id", value=body.user_id),),
            update={
                "banned": False,
                "banReason": None,
                "banExpires": None,
                "updatedAt": int(time.time()),
            },
        )
        if not user:
            raise APIError(404, "USER_NOT_FOUND")
        return {"user": user}

    async def impersonate_user(ctx: EndpointContext) -> dict[str, Any]:
        caller = await _require_admin(
            ctx, opts, roles_map, error_code="YOU_ARE_NOT_ALLOWED_TO_IMPERSONATE_USERS"
        )
        body: ImpersonateBody = ctx.body
        target = await ctx.auth.adapter.find_one(
            model="user",
            where=(Where(field="id", value=body.user_id),),
        )
        if not target:
            raise APIError(404, "USER_NOT_FOUND")
        # Block impersonating other admins (unless caller has impersonate-admins).
        target_role = _resolve_role(opts, roles_map, target)
        if _is_admin(opts, target):
            caller_role = _resolve_role(opts, roles_map, caller)
            allowed = caller_role.authorize({"user": ("impersonate-admins",)})
            if not allowed.success:
                raise APIError(403, "YOU_CANNOT_IMPERSONATE_ADMINS")
        # Create the impersonation session (1-hour default).
        session, cookies = await create_session(
            ctx.auth,
            user_id=target["id"],
            ip_address=ctx.request.headers.get("x-forwarded-for"),
            user_agent=ctx.request.headers.get("user-agent"),
        )
        # Persist `impersonatedBy` on the session row.
        await ctx.auth.adapter.update(
            model="session",
            where=(Where(field="id", value=session.id),),
            update={"impersonatedBy": caller["id"]},
        )
        # Stash the admin's original token in a separate cookie so we can restore on
        # stop-impersonating.
        admin_token_signed = sign(ctx.session.token, secret=ctx.auth.secret)  # type: ignore[union-attr]
        attrs = CookieAttributes(
            path="/",
            max_age=ctx.auth.options.session.expires_in,
            http_only=True,
            secure=ctx.auth.base_url.startswith("https"),
            same_site="lax",
        )
        ctx.set_cookies.extend(cookies)
        ctx.set_cookies.append((ADMIN_IMPERSONATION_COOKIE, admin_token_signed, attrs))
        return {
            "session": {
                "id": session.id,
                "expiresAt": session.expires_at,
                "impersonatedBy": caller["id"],
            },
            "user": target,
        }

    async def stop_impersonating(ctx: EndpointContext) -> dict[str, Any]:
        from kernia.cookies import verify

        if ctx.session is None:
            raise APIError(401, "UNAUTHORIZED")
        session_row = await ctx.auth.adapter.find_one(
            model="session",
            where=(Where(field="id", value=ctx.session.id),),
        )
        if not session_row or not session_row.get("impersonatedBy"):
            raise APIError(400, "NOT_IMPERSONATING")
        admin_cookie = ctx.request.cookies.get(ADMIN_IMPERSONATION_COOKIE, "")
        admin_token = verify(admin_cookie, secret=ctx.auth.secret) if admin_cookie else None
        # Revoke the impersonation session.
        await ctx.auth.adapter.delete_many(
            model="session",
            where=(Where(field="id", value=ctx.session.id),),
        )
        clear_admin = CookieAttributes(
            path="/", max_age=0, http_only=True, secure=False, same_site="lax"
        )
        ctx.set_cookies.append((ADMIN_IMPERSONATION_COOKIE, "", clear_admin))
        if not admin_token:
            # No restorable admin session; clear cookies.
            clear = CookieAttributes(
                path="/", max_age=0, http_only=True, secure=False, same_site="lax"
            )
            ctx.set_cookies.append((SESSION_TOKEN_COOKIE, "", clear))
            ctx.set_cookies.append((DONT_REMEMBER_COOKIE, "", clear))
            return {"success": True}
        # Re-attach the admin session cookie.
        attrs = CookieAttributes(
            path="/",
            max_age=ctx.auth.options.session.expires_in,
            http_only=True,
            secure=ctx.auth.base_url.startswith("https"),
            same_site="lax",
        )
        ctx.set_cookies.append((SESSION_TOKEN_COOKIE, sign(admin_token, secret=ctx.auth.secret), attrs))
        return {"success": True}

    async def list_user_sessions(ctx: EndpointContext) -> dict[str, Any]:
        await _require_admin(
            ctx, opts, roles_map, error_code="YOU_ARE_NOT_ALLOWED_TO_LIST_USERS_SESSIONS"
        )
        body: ListUserSessionsBody = ctx.body
        rows = await ctx.auth.adapter.find_many(
            model="session",
            where=(Where(field="userId", value=body.user_id),),
        )
        return {"sessions": rows}

    async def revoke_user_session(ctx: EndpointContext) -> dict[str, Any]:
        await _require_admin(
            ctx, opts, roles_map, error_code="YOU_ARE_NOT_ALLOWED_TO_REVOKE_USERS_SESSIONS"
        )
        body: RevokeUserSessionBody = ctx.body
        await ctx.auth.adapter.delete_many(
            model="session",
            where=(Where(field="id", value=body.session_id),),
        )
        return {"success": True}

    async def revoke_user_sessions(ctx: EndpointContext) -> dict[str, Any]:
        await _require_admin(
            ctx, opts, roles_map, error_code="YOU_ARE_NOT_ALLOWED_TO_REVOKE_USERS_SESSIONS"
        )
        body: RevokeUserSessionsBody = ctx.body
        n = await ctx.auth.adapter.delete_many(
            model="session",
            where=(Where(field="userId", value=body.user_id),),
        )
        return {"revoked": n}

    async def set_user_password(ctx: EndpointContext) -> dict[str, Any]:
        await _require_admin(
            ctx, opts, roles_map, error_code="YOU_ARE_NOT_ALLOWED_TO_SET_USERS_PASSWORD"
        )
        body: SetPasswordBody = ctx.body
        await ctx.auth.adapter.update(
            model="account",
            where=(
                Where(field="userId", value=body.user_id),
                Where(field="providerId", value="credential"),
            ),
            update={"password": hash_password(body.new_password)},
        )
        return {"success": True}

    async def remove_user(ctx: EndpointContext) -> dict[str, Any]:
        caller = await _require_admin(
            ctx, opts, roles_map, error_code="YOU_ARE_NOT_ALLOWED_TO_DELETE_USERS"
        )
        body: RemoveUserBody = ctx.body
        if body.user_id == caller["id"]:
            raise APIError(400, "YOU_CANNOT_REMOVE_YOURSELF")
        await ctx.auth.adapter.delete_many(
            model="session",
            where=(Where(field="userId", value=body.user_id),),
        )
        await ctx.auth.adapter.delete_many(
            model="account",
            where=(Where(field="userId", value=body.user_id),),
        )
        await ctx.auth.adapter.delete_many(
            model="user",
            where=(Where(field="id", value=body.user_id),),
        )
        return {"success": True}

    async def has_permission(ctx: EndpointContext) -> dict[str, Any]:
        if ctx.session is None:
            raise APIError(401, "UNAUTHORIZED")
        body: HasPermissionBody = ctx.body
        target_id = body.user_id or ctx.session.user_id
        user = await ctx.auth.adapter.find_one(
            model="user",
            where=(Where(field="id", value=target_id),),
        )
        if user is None:
            return {"success": False, "error": "user not found"}
        if user["id"] in opts.admin_user_ids:
            return {"success": True}
        role = _resolve_role(opts, roles_map, user)
        result = role.authorize(body.permissions)
        return {"success": result.success, "error": result.error}

    return (
        create_auth_endpoint(
            "/admin/list-users",
            EndpointOptions(method="POST", body=ListUsersBody),
            list_users,
        ),
        create_auth_endpoint(
            "/admin/get-user",
            EndpointOptions(method="POST", body=GetUserBody),
            get_user,
        ),
        create_auth_endpoint(
            "/admin/create-user",
            EndpointOptions(method="POST", body=CreateUserBody),
            create_user,
        ),
        create_auth_endpoint(
            "/admin/update-user",
            EndpointOptions(method="POST", body=UpdateUserBody),
            update_user,
        ),
        create_auth_endpoint(
            "/admin/set-role",
            EndpointOptions(method="POST", body=SetRoleBody),
            set_role,
        ),
        create_auth_endpoint(
            "/admin/ban-user",
            EndpointOptions(method="POST", body=BanUserBody),
            ban_user,
        ),
        create_auth_endpoint(
            "/admin/unban-user",
            EndpointOptions(method="POST", body=UnbanUserBody),
            unban_user,
        ),
        create_auth_endpoint(
            "/admin/impersonate-user",
            EndpointOptions(method="POST", body=ImpersonateBody),
            impersonate_user,
        ),
        create_auth_endpoint(
            "/admin/stop-impersonating",
            EndpointOptions(method="POST"),
            stop_impersonating,
        ),
        create_auth_endpoint(
            "/admin/list-user-sessions",
            EndpointOptions(method="POST", body=ListUserSessionsBody),
            list_user_sessions,
        ),
        create_auth_endpoint(
            "/admin/revoke-user-session",
            EndpointOptions(method="POST", body=RevokeUserSessionBody),
            revoke_user_session,
        ),
        create_auth_endpoint(
            "/admin/revoke-user-sessions",
            EndpointOptions(method="POST", body=RevokeUserSessionsBody),
            revoke_user_sessions,
        ),
        create_auth_endpoint(
            "/admin/set-user-password",
            EndpointOptions(method="POST", body=SetPasswordBody),
            set_user_password,
        ),
        create_auth_endpoint(
            "/admin/remove-user",
            EndpointOptions(method="POST", body=RemoveUserBody),
            remove_user,
        ),
        create_auth_endpoint(
            "/admin/has-permission",
            EndpointOptions(method="POST", body=HasPermissionBody),
            has_permission,
        ),
    )


__all__ = ["build_endpoints", "ADMIN_IMPERSONATION_COOKIE"]
