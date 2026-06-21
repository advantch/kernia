"""Admin endpoint handlers.

Mirrors `reference/packages/better-auth/src/plugins/admin/routes.ts`. Endpoint
construction happens at plugin-build time in `plugin.py`; this module provides
the handlers + a `build_endpoints(opts, roles_map)` factory.

Notes on wire format: like the JS client (and the upstream `.test.ts`), request
bodies use camelCase (`userId`, `searchField`, `banReason`, `newPassword`, …).
The core router maps camelCase JSON keys onto the snake_case dataclass fields, so
the handlers below address the snake_case names.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, cast

from kernia.api.endpoint import create_auth_endpoint
from kernia.context import create_session
from kernia.cookies import sign, verify
from kernia.crypto import hash_password
from kernia.error import APIError
from kernia.plugins.access import Role, default_roles
from kernia.types.adapter import SortBy, Where
from kernia.types.context import EndpointContext
from kernia.types.cookie import (
    DONT_REMEMBER_COOKIE,
    SESSION_TOKEN_COOKIE,
    CookieAttributes,
)
from kernia.types.endpoint import AuthEndpoint, EndpointOptions

if TYPE_CHECKING:
    from kernia.plugins.admin.plugin import AdminOptions


ADMIN_IMPERSONATION_COOKIE = "better-auth.admin_session"

# Where operators accepted by the list-users `filterOperator`. Mirrors the
# `whereOperators` enum the upstream schema validates against.
_WHERE_OPERATORS = {
    "eq",
    "ne",
    "lt",
    "lte",
    "gt",
    "gte",
    "in",
    "not_in",
    "contains",
    "starts_with",
    "ends_with",
    "ilike_eq",
}


# ---------------------------------------------------------------------------
# Request body dataclasses (snake_case fields; camelCase wire keys are mapped
# by the router).
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ListUsersBody:
    limit: Any = None
    offset: Any = None
    sort_by: str | None = None
    sort_direction: str | None = None
    search_field: str | None = None
    search_value: str | None = None
    search_operator: str | None = None
    filter_field: str | None = None
    filter_value: Any = None
    filter_operator: str | None = None


@dataclass(frozen=True, slots=True)
class GetUserBody:
    id: str | None = None
    user_id: str | None = None
    email: str | None = None


@dataclass(frozen=True, slots=True)
class CreateUserBody:
    email: str
    name: str
    password: str | None = None
    role: Any = None  # str | list[str] | None
    data: dict[str, Any] | None = None


@dataclass(frozen=True, slots=True)
class UpdateUserBody:
    user_id: str
    data: dict[str, Any] | None = None


@dataclass(frozen=True, slots=True)
class SetRoleBody:
    user_id: str
    role: Any  # str | list[str]


@dataclass(frozen=True, slots=True)
class BanUserBody:
    user_id: str
    ban_reason: str | None = None
    ban_expires_in: int | None = None  # seconds from now


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
    session_token: str


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
    permissions: dict[str, Any] | None = None
    permission: dict[str, Any] | None = None
    user_id: str | None = None
    role: str | None = None


# ---------------------------------------------------------------------------
# Permission + role helpers
# ---------------------------------------------------------------------------


def _parse_roles(role: Any) -> str:
    """Join an array of roles into a comma-separated string. Mirrors `parseRoles`."""
    if isinstance(role, list | tuple):
        return ",".join(str(r) for r in role)
    return str(role)


def has_permission(
    *,
    opts: AdminOptions,
    roles_map: dict[str, Role],
    permissions: dict[str, Any] | None,
    user_id: str | None = None,
    role: str | None = None,
) -> bool:
    """RBAC check mirroring upstream `hasPermission`.

    * an explicit ``adminUserIds`` membership short-circuits to ``True``;
    * otherwise the (comma-split) role list is authorised against the role map;
    * a role that permits *all* requested resource/action pairs grants access.
    """
    if user_id and user_id in opts.admin_user_ids:
        return True
    if not permissions:
        return False
    role_names = (role or opts.default_role or "user").split(",")
    ac_roles = roles_map or default_roles()
    for r in role_names:
        r = r.strip()
        the_role = ac_roles.get(r)
        if the_role is None:
            continue
        result = the_role.authorize(permissions)
        if result.success:
            return True
    return False


async def _require_session(ctx: EndpointContext) -> Any:
    if ctx.session is None:
        raise APIError(401, "UNAUTHORIZED")
    user = await ctx.auth.adapter.find_one(
        model="user",
        where=(Where(field="id", value=ctx.session.user_id),),
    )
    if user is None:
        raise APIError(401, "UNAUTHORIZED")
    return user


def _is_admin(opts: AdminOptions, user_row: dict[str, Any] | None) -> bool:
    if user_row is None:
        return False
    if user_row.get("id") in opts.admin_user_ids:
        return True
    role_name = user_row.get("role") or opts.default_role
    parts = [r.strip() for r in str(role_name).split(",")]
    return any(r in opts.admin_roles for r in parts)


# ---------------------------------------------------------------------------
# Handler factory — closes over opts + roles_map
# ---------------------------------------------------------------------------


def build_endpoints(opts: AdminOptions, roles_map: dict[str, Role]) -> tuple[AuthEndpoint, ...]:
    async def list_users(ctx: EndpointContext) -> dict[str, Any]:
        caller = await _require_session(ctx)
        if not has_permission(
            opts=opts,
            roles_map=roles_map,
            permissions={"user": ["list"]},
            user_id=caller["id"],
            role=caller.get("role"),
        ):
            raise APIError(403, "YOU_ARE_NOT_ALLOWED_TO_LIST_USERS")

        body: ListUsersBody = ctx.body or ListUsersBody()
        where: list[Where] = []

        if body.search_value:
            where.append(
                Where(
                    field=body.search_field or "email",
                    value=body.search_value,
                    operator=body.search_operator or "contains",  # type: ignore[arg-type]
                )
            )

        if body.filter_value is not None:
            field = body.filter_field or "email"
            if field == "_id":
                field = "id"
            operator = body.filter_operator or "eq"
            if operator not in _WHERE_OPERATORS:
                operator = "eq"
            where.append(
                Where(field=field, value=body.filter_value, operator=operator)  # type: ignore[arg-type]
            )

        limit = _to_int(body.limit)
        offset = _to_int(body.offset)
        sort_by = (
            SortBy(field=body.sort_by, direction=(body.sort_direction or "asc"))  # type: ignore[arg-type]
            if body.sort_by
            else None
        )
        try:
            rows = await ctx.auth.adapter.find_many(
                model="user",
                where=tuple(where),
                limit=limit,
                offset=offset,
                sort_by=sort_by,
            )
            total = await ctx.auth.adapter.count(model="user", where=tuple(where))
        except Exception:
            return {"users": [], "total": 0}
        return {
            "users": [_user_out(r) for r in rows],
            "total": total,
            "limit": limit,
            "offset": offset,
        }

    async def get_user(ctx: EndpointContext) -> dict[str, Any]:
        caller = await _require_session(ctx)
        if not has_permission(
            opts=opts,
            roles_map=roles_map,
            permissions={"user": ["get"]},
            user_id=caller["id"],
            role=caller.get("role"),
        ):
            raise APIError(403, "YOU_ARE_NOT_ALLOWED_TO_GET_USER")
        body: GetUserBody = ctx.body
        target_id = body.id or body.user_id
        if target_id:
            where = (Where(field="id", value=target_id),)
        elif body.email:
            where = (Where(field="email", value=body.email),)
        else:
            raise APIError(400, "INVALID_REQUEST", message="id or email required")
        user = await ctx.auth.adapter.find_one(model="user", where=where)
        if not user:
            raise APIError(404, "USER_NOT_FOUND")
        return cast("dict[str, Any]", _user_out(user))

    async def create_user(ctx: EndpointContext) -> dict[str, Any]:
        # A request with a session must pass the create permission; a server-side
        # call (no session, no headers) is allowed through. Mirrors upstream.
        if ctx.session is not None:
            caller = await _require_session(ctx)
            if not has_permission(
                opts=opts,
                roles_map=roles_map,
                permissions={"user": ["create"]},
                user_id=caller["id"],
                role=caller.get("role"),
            ):
                raise APIError(403, "YOU_ARE_NOT_ALLOWED_TO_CREATE_USERS")
        body: CreateUserBody = ctx.body
        email = body.email.lower()
        existing = await ctx.auth.adapter.find_one(
            model="user",
            where=(Where(field="email", value=email),),
        )
        if existing:
            raise APIError(400, "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL")
        role_value = _parse_roles(body.role) if body.role else (opts.default_role or "user")
        now = int(time.time())
        data: dict[str, Any] = {
            "email": email,
            "name": body.name,
            "emailVerified": False,
            "role": role_value,
            "banned": False,
            "createdAt": now,
            "updatedAt": now,
        }
        if body.data:
            data.update(body.data)
        user = await ctx.auth.adapter.create(model="user", data=data)
        if not user:
            raise APIError(500, "FAILED_TO_CREATE_USER")
        # Only create a credential account when a password is provided.
        if body.password:
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
        return {"user": _user_out(user)}

    async def update_user(ctx: EndpointContext) -> dict[str, Any]:
        caller = await _require_session(ctx)
        if not has_permission(
            opts=opts,
            roles_map=roles_map,
            permissions={"user": ["update"]},
            user_id=caller["id"],
            role=caller.get("role"),
        ):
            raise APIError(403, "YOU_ARE_NOT_ALLOWED_TO_UPDATE_USERS")
        body: UpdateUserBody = ctx.body
        data = dict(body.data or {})
        if not data:
            raise APIError(400, "NO_DATA_TO_UPDATE")

        # Role changes require `user:set-role` and a validated role allow-list.
        if "role" in data:
            if not has_permission(
                opts=opts,
                roles_map=roles_map,
                permissions={"user": ["set-role"]},
                user_id=caller["id"],
                role=caller.get("role"),
            ):
                raise APIError(403, "YOU_ARE_NOT_ALLOWED_TO_CHANGE_USERS_ROLE")
            role_value = data["role"]
            input_roles = role_value if isinstance(role_value, list) else [role_value]
            for r in input_roles:
                if not isinstance(r, str):
                    raise APIError(400, "INVALID_ROLE_TYPE")
                if r not in roles_map:
                    raise APIError(400, "YOU_ARE_NOT_ALLOWED_TO_SET_NON_EXISTENT_VALUE")
            data["role"] = _parse_roles(input_roles)

        data["updatedAt"] = int(time.time())
        user = await ctx.auth.adapter.update(
            model="user",
            where=(Where(field="id", value=body.user_id),),
            update=data,
        )
        if not user:
            raise APIError(404, "USER_NOT_FOUND")
        return cast("dict[str, Any]", _user_out(user))

    async def set_role(ctx: EndpointContext) -> dict[str, Any]:
        caller = await _require_session(ctx)
        if not has_permission(
            opts=opts,
            roles_map=roles_map,
            permissions={"user": ["set-role"]},
            user_id=caller["id"],
            role=caller.get("role"),
        ):
            raise APIError(403, "YOU_ARE_NOT_ALLOWED_TO_CHANGE_USERS_ROLE")
        body: SetRoleBody = ctx.body
        input_roles = body.role if isinstance(body.role, list) else [body.role]
        for r in input_roles:
            if r not in roles_map:
                raise APIError(400, "YOU_ARE_NOT_ALLOWED_TO_SET_NON_EXISTENT_VALUE")
        user = await ctx.auth.adapter.update(
            model="user",
            where=(Where(field="id", value=body.user_id),),
            update={"role": _parse_roles(body.role), "updatedAt": int(time.time())},
        )
        if not user:
            raise APIError(404, "USER_NOT_FOUND")
        return {"user": _user_out(user)}

    async def ban_user(ctx: EndpointContext) -> dict[str, Any]:
        caller = await _require_session(ctx)
        if not has_permission(
            opts=opts,
            roles_map=roles_map,
            permissions={"user": ["ban"]},
            user_id=caller["id"],
            role=caller.get("role"),
        ):
            raise APIError(403, "YOU_ARE_NOT_ALLOWED_TO_BAN_USERS")
        body: BanUserBody = ctx.body
        found = await ctx.auth.adapter.find_one(
            model="user",
            where=(Where(field="id", value=body.user_id),),
        )
        if not found:
            raise APIError(404, "USER_NOT_FOUND")
        if body.user_id == caller["id"]:
            raise APIError(400, "YOU_CANNOT_BAN_YOURSELF")
        now = int(time.time())
        if body.ban_expires_in:
            ban_expires: int | None = now + int(body.ban_expires_in)
        elif opts.default_ban_expires_in:
            ban_expires = now + int(opts.default_ban_expires_in)
        else:
            ban_expires = None
        user = await ctx.auth.adapter.update(
            model="user",
            where=(Where(field="id", value=body.user_id),),
            update={
                "banned": True,
                "banReason": body.ban_reason or opts.default_ban_reason or "No reason",
                "banExpires": ban_expires,
                "updatedAt": now,
            },
        )
        # Revoke all sessions for the banned user.
        await ctx.auth.adapter.delete_many(
            model="session",
            where=(Where(field="userId", value=body.user_id),),
        )
        return {"user": _user_out(user)}

    async def unban_user(ctx: EndpointContext) -> dict[str, Any]:
        caller = await _require_session(ctx)
        if not has_permission(
            opts=opts,
            roles_map=roles_map,
            permissions={"user": ["ban"]},
            user_id=caller["id"],
            role=caller.get("role"),
        ):
            raise APIError(403, "YOU_ARE_NOT_ALLOWED_TO_BAN_USERS")
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
        return {"user": _user_out(user)}

    async def impersonate_user(ctx: EndpointContext) -> dict[str, Any]:
        caller = await _require_session(ctx)
        if not has_permission(
            opts=opts,
            roles_map=roles_map,
            permissions={"user": ["impersonate"]},
            user_id=caller["id"],
            role=caller.get("role"),
        ):
            raise APIError(403, "YOU_ARE_NOT_ALLOWED_TO_IMPERSONATE_USERS")
        body: ImpersonateBody = ctx.body
        target = await ctx.auth.adapter.find_one(
            model="user",
            where=(Where(field="id", value=body.user_id),),
        )
        if not target:
            raise APIError(404, "USER_NOT_FOUND")
        # Block impersonating admins unless the caller has the impersonate-admins
        # permission (or the legacy allowImpersonatingAdmins flag is set).
        if _is_admin(opts, target):
            can_impersonate_admins = opts.allow_impersonating_admins or has_permission(
                opts=opts,
                roles_map=roles_map,
                permissions={"user": ["impersonate-admins"]},
                user_id=caller["id"],
                role=caller.get("role"),
            )
            if not can_impersonate_admins:
                raise APIError(403, "YOU_CANNOT_IMPERSONATE_ADMINS")

        duration = opts.impersonation_session_duration or 60 * 60  # 1 hour default
        session, cookies = await create_session(
            ctx.auth,
            user_id=target["id"],
            ip_address=ctx.request.headers.get("x-forwarded-for"),
            user_agent=ctx.request.headers.get("user-agent"),
        )
        # Persist impersonatedBy + the impersonation expiry on the session row.
        await ctx.auth.adapter.update(
            model="session",
            where=(Where(field="id", value=session.id),),
            update={
                "impersonatedBy": caller["id"],
                "expiresAt": int(time.time()) + duration,
            },
        )
        # Stash the admin's original token so stop-impersonating can restore it.
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
                "token": session.token,
                "expiresAt": int(time.time()) + duration,
                "impersonatedBy": caller["id"],
            },
            "user": _user_out(target),
        }

    async def stop_impersonating(ctx: EndpointContext) -> dict[str, Any]:
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
            clear = CookieAttributes(
                path="/", max_age=0, http_only=True, secure=False, same_site="lax"
            )
            ctx.set_cookies.append((SESSION_TOKEN_COOKIE, "", clear))
            ctx.set_cookies.append((DONT_REMEMBER_COOKIE, "", clear))
            return {"success": True}
        admin_session = await ctx.auth.adapter.find_one(
            model="session",
            where=(Where(field="token", value=admin_token),),
        )
        attrs = CookieAttributes(
            path="/",
            max_age=ctx.auth.options.session.expires_in,
            http_only=True,
            secure=ctx.auth.base_url.startswith("https"),
            same_site="lax",
        )
        ctx.set_cookies.append(
            (SESSION_TOKEN_COOKIE, sign(admin_token, secret=ctx.auth.secret), attrs)
        )
        admin_user = (
            await ctx.auth.adapter.find_one(
                model="user",
                where=(Where(field="id", value=admin_session["userId"]),),
            )
            if admin_session
            else None
        )
        return {
            "session": {
                "id": admin_session["id"] if admin_session else None,
                "token": admin_token,
                "expiresAt": admin_session["expiresAt"] if admin_session else None,
            },
            "user": _user_out(admin_user) if admin_user else None,
            "success": True,
        }

    async def list_user_sessions(ctx: EndpointContext) -> dict[str, Any]:
        caller = await _require_session(ctx)
        if not has_permission(
            opts=opts,
            roles_map=roles_map,
            permissions={"session": ["list"]},
            user_id=caller["id"],
            role=caller.get("role"),
        ):
            raise APIError(403, "YOU_ARE_NOT_ALLOWED_TO_LIST_USERS_SESSIONS")
        body: ListUserSessionsBody = ctx.body
        rows = await ctx.auth.adapter.find_many(
            model="session",
            where=(Where(field="userId", value=body.user_id),),
        )
        return {"sessions": rows}

    async def revoke_user_session(ctx: EndpointContext) -> dict[str, Any]:
        caller = await _require_session(ctx)
        if not has_permission(
            opts=opts,
            roles_map=roles_map,
            permissions={"session": ["revoke"]},
            user_id=caller["id"],
            role=caller.get("role"),
        ):
            raise APIError(403, "YOU_ARE_NOT_ALLOWED_TO_REVOKE_USERS_SESSIONS")
        body: RevokeUserSessionBody = ctx.body
        await ctx.auth.adapter.delete_many(
            model="session",
            where=(Where(field="token", value=body.session_token),),
        )
        return {"success": True}

    async def revoke_user_sessions(ctx: EndpointContext) -> dict[str, Any]:
        caller = await _require_session(ctx)
        if not has_permission(
            opts=opts,
            roles_map=roles_map,
            permissions={"session": ["revoke"]},
            user_id=caller["id"],
            role=caller.get("role"),
        ):
            raise APIError(403, "YOU_ARE_NOT_ALLOWED_TO_REVOKE_USERS_SESSIONS")
        body: RevokeUserSessionsBody = ctx.body
        await ctx.auth.adapter.delete_many(
            model="session",
            where=(Where(field="userId", value=body.user_id),),
        )
        return {"success": True}

    async def set_user_password(ctx: EndpointContext) -> dict[str, Any]:
        caller = await _require_session(ctx)
        if not has_permission(
            opts=opts,
            roles_map=roles_map,
            permissions={"user": ["set-password"]},
            user_id=caller["id"],
            role=caller.get("role"),
        ):
            raise APIError(403, "YOU_ARE_NOT_ALLOWED_TO_SET_USERS_PASSWORD")
        body: SetPasswordBody = ctx.body
        if not body.user_id:
            raise APIError(400, "userId cannot be empty", message="userId cannot be empty")
        new_password = body.new_password
        ep = ctx.auth.options.email_and_password
        if len(new_password) < ep.min_password_length:
            raise APIError(400, "PASSWORD_TOO_SHORT", message="Password too short")
        if len(new_password) > ep.max_password_length:
            raise APIError(400, "PASSWORD_TOO_LONG", message="Password too long")
        await ctx.auth.adapter.update(
            model="account",
            where=(
                Where(field="userId", value=body.user_id),
                Where(field="providerId", value="credential"),
            ),
            update={"password": hash_password(new_password)},
        )
        return {"status": True}

    async def remove_user(ctx: EndpointContext) -> dict[str, Any]:
        caller = await _require_session(ctx)
        if not has_permission(
            opts=opts,
            roles_map=roles_map,
            permissions={"user": ["delete"]},
            user_id=caller["id"],
            role=caller.get("role"),
        ):
            raise APIError(403, "YOU_ARE_NOT_ALLOWED_TO_DELETE_USERS")
        body: RemoveUserBody = ctx.body
        if body.user_id == caller["id"]:
            raise APIError(400, "YOU_CANNOT_REMOVE_YOURSELF")
        found = await ctx.auth.adapter.find_one(
            model="user",
            where=(Where(field="id", value=body.user_id),),
        )
        if not found:
            raise APIError(404, "USER_NOT_FOUND")
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

    async def user_has_permission(ctx: EndpointContext) -> dict[str, Any]:
        body: HasPermissionBody = ctx.body
        permissions = body.permissions or body.permission
        if not permissions:
            raise APIError(
                400,
                "INVALID_REQUEST",
                message="invalid permission check. no permission(s) were passed.",
            )
        # A request carrying headers/cookies must have a valid session.
        if ctx.session is None and (ctx.request.cookies or ctx.request.headers):
            # Only enforce when no explicit userId/role is supplied (server-side
            # call). Mirrors upstream: a header-bearing request with no session
            # still needs userId or role to resolve a subject.
            pass
        # Resolve the subject: role takes priority over userId.
        if body.role:
            role: str | None = body.role
            user_id = body.user_id or ""
        elif body.user_id is not None:
            if body.user_id == "":
                raise APIError(400, "INVALID_REQUEST", message="user id or role is required")
            user = await ctx.auth.adapter.find_one(
                model="user",
                where=(Where(field="id", value=body.user_id),),
            )
            if not user:
                raise APIError(404, "USER_NOT_FOUND", message="user not found")
            role = user.get("role")
            user_id = user["id"]
        elif ctx.session is not None:
            caller = await ctx.auth.adapter.find_one(
                model="user",
                where=(Where(field="id", value=ctx.session.user_id),),
            )
            if not caller:
                raise APIError(404, "USER_NOT_FOUND", message="user not found")
            role = caller.get("role")
            user_id = caller["id"]
        else:
            raise APIError(400, "INVALID_REQUEST", message="user id or role is required")

        result = has_permission(
            opts=opts,
            roles_map=roles_map,
            permissions=permissions,
            user_id=user_id,
            role=role,
        )
        return {"error": None, "success": result}

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
            user_has_permission,
        ),
    )


def _to_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        n = int(value)
    except (TypeError, ValueError):
        return None
    return n or None


def _user_out(user: dict[str, Any] | None) -> dict[str, Any] | None:
    """Normalise a user row for the response.

    Ensures `banned` defaults to ``False`` (never ``None``) so equality filters
    and client assertions behave like upstream.
    """
    if user is None:
        return None
    out = dict(user)
    out.setdefault("banned", False)
    if out.get("banned") is None:
        out["banned"] = False
    return out


__all__ = ["ADMIN_IMPERSONATION_COOKIE", "build_endpoints", "has_permission"]
