"""Organization plugin endpoint definitions + handlers.

Mirrors the route files under
``reference/packages/better-auth/src/plugins/organization/routes/``:
``crud-org.ts``, ``crud-members.ts``, ``crud-invites.ts``, ``crud-team.ts``, and
``crud-access-control.ts``.

The handlers are intentionally flat and dependency-light: each one looks up the
records it needs via :class:`CustomAdapter`, enforces role-based authorization via
:func:`has_permission` from :mod:`access_control`, and returns plain dicts. The
membership before-hook (see :mod:`hooks`) guarantees the caller is a member of
the target org by the time these handlers run, so handlers focus on the policy
logic rather than re-checking membership.
"""

from __future__ import annotations

import secrets
import time
from typing import Any

from pydantic import BaseModel, ConfigDict

from kernia.api.endpoint import create_auth_endpoint
from kernia.error import APIError
from kernia.events import MemberEvent, get_bus
from kernia.plugins.organization.access_control import (
    DEFAULT_ROLES,
    DEFAULT_STATEMENTS,
    has_permission,
    merge_dynamic_roles,
)
from kernia.types.adapter import Where
from kernia.types.context import EndpointContext
from kernia.types.endpoint import AuthEndpoint, EndpointOptions

# ---------------------------------------------------------------------------
# Pydantic bodies
# ---------------------------------------------------------------------------


class CreateOrganizationBody(BaseModel):
    model_config = ConfigDict(extra="ignore")

    name: str
    slug: str | None = None
    logo: str | None = None
    metadata: dict[str, Any] | None = None
    keepCurrentActiveOrganization: bool = False


class UpdateOrganizationBody(BaseModel):
    model_config = ConfigDict(extra="ignore")

    organizationId: str
    data: dict[str, Any]


class DeleteOrganizationBody(BaseModel):
    organizationId: str


class SetActiveOrganizationBody(BaseModel):
    organizationId: str | None = None


class InviteMemberBody(BaseModel):
    organizationId: str
    email: str
    role: str = "member"


class CancelInvitationBody(BaseModel):
    invitationId: str


class AcceptInvitationBody(BaseModel):
    invitationId: str


class RejectInvitationBody(BaseModel):
    invitationId: str


class RemoveMemberBody(BaseModel):
    organizationId: str
    memberIdOrEmail: str


class UpdateMemberRoleBody(BaseModel):
    organizationId: str
    memberId: str
    role: str


class LeaveOrganizationBody(BaseModel):
    organizationId: str


class HasPermissionBody(BaseModel):
    organizationId: str
    permissions: dict[str, list[str]]


class CreateTeamBody(BaseModel):
    organizationId: str
    name: str


class UpdateTeamBody(BaseModel):
    organizationId: str
    teamId: str
    name: str


class DeleteTeamBody(BaseModel):
    organizationId: str
    teamId: str


class AddTeamMemberBody(BaseModel):
    organizationId: str
    teamId: str
    userId: str


class RemoveTeamMemberBody(BaseModel):
    organizationId: str
    teamId: str
    userId: str


class CreateRoleBody(BaseModel):
    organizationId: str
    role: str
    permissions: dict[str, list[str]]


class UpdateRoleBody(BaseModel):
    organizationId: str
    role: str
    permissions: dict[str, list[str]]


class DeleteRoleBody(BaseModel):
    organizationId: str
    role: str


class CheckSlugBody(BaseModel):
    slug: str


class SetActiveTeamBody(BaseModel):
    teamId: str | None = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _now() -> int:
    return int(time.time())


def _slugify(name: str) -> str:
    out = []
    for ch in name.lower():
        if ch.isalnum():
            out.append(ch)
        elif ch in "- _":
            out.append("-")
    s = "".join(out).strip("-")
    return s or secrets.token_hex(4)


async def _find_slug_collision(ctx: EndpointContext, slug: str) -> bool:
    """Slug uniqueness is case-insensitive."""
    existing = await ctx.auth.adapter.find_one(
        model="organization",
        where=(Where(field="slug", value=slug.lower()),),
    )
    return existing is not None


async def _get_member(
    ctx: EndpointContext, *, organization_id: str, user_id: str
) -> dict[str, Any] | None:
    return await ctx.auth.adapter.find_one(
        model="member",
        where=(
            Where(field="organizationId", value=organization_id),
            Where(field="userId", value=user_id),
        ),
    )


async def _require_caller_member(
    ctx: EndpointContext, organization_id: str
) -> dict[str, Any]:
    if ctx.session is None:
        raise APIError(401, "UNAUTHORIZED")
    member = await _get_member(
        ctx, organization_id=organization_id, user_id=ctx.session.user_id
    )
    if not member:
        raise APIError(403, "NOT_MEMBER")
    return member


async def _resolve_role_table(
    ctx: EndpointContext, organization_id: str
) -> dict[str, Any]:
    """Return the effective role table for an organization.

    Built-in roles always present; when dynamic AC is on, organization-scoped
    custom roles from the ``organizationRole`` table are layered on top.
    """
    options = _options(ctx)
    if not options.get("dynamic_access_control_enabled"):
        return dict(DEFAULT_ROLES)
    rows = await ctx.auth.adapter.find_many(
        model="organizationRole",
        where=(Where(field="organizationId", value=organization_id),),
    )
    return merge_dynamic_roles(rows)


def _options(ctx: EndpointContext) -> dict[str, Any]:
    """Resolve plugin config.

    Reads from ``options.advanced["organization"]`` first (where the async
    plugin init writes its merged config); falls back to the plugin instance's
    ``_config`` attribute, which is set synchronously at construction time so
    that handlers work even before the init task has run.
    """
    advanced = ctx.auth.options.advanced.get("organization")
    if advanced:
        return advanced
    for plugin in ctx.auth.plugins:
        if getattr(plugin, "id", None) == "organization":
            cfg = getattr(plugin, "_config", None)
            if cfg:
                return dict(cfg)
    return {}


async def _enforce_permission(
    ctx: EndpointContext,
    *,
    organization_id: str,
    required: dict[str, list[str]],
    member: dict[str, Any] | None = None,
) -> None:
    member = member or await _require_caller_member(ctx, organization_id)
    role_table = await _resolve_role_table(ctx, organization_id)
    if not has_permission(member["role"], required, role_table):
        raise APIError(403, "NOT_ALLOWED")


async def _count_owners(ctx: EndpointContext, organization_id: str) -> int:
    return await ctx.auth.adapter.count(
        model="member",
        where=(
            Where(field="organizationId", value=organization_id),
            Where(field="role", value="owner"),
        ),
    )


async def _set_active_organization(
    ctx: EndpointContext, *, session_id: str, organization_id: str | None
) -> None:
    await ctx.auth.adapter.update(
        model="session",
        where=(Where(field="id", value=session_id),),
        update={"activeOrganizationId": organization_id},
    )


async def _set_active_team(
    ctx: EndpointContext, *, session_id: str, team_id: str | None
) -> None:
    await ctx.auth.adapter.update(
        model="session",
        where=(Where(field="id", value=session_id),),
        update={"activeTeamId": team_id},
    )


async def _session_row(ctx: EndpointContext) -> dict[str, Any] | None:
    """Fetch the raw session row so we can read extension columns
    (activeOrganizationId / activeTeamId) that the typed Session object omits.
    """
    if ctx.session is None:
        return None
    return await ctx.auth.adapter.find_one(
        model="session", where=(Where(field="id", value=ctx.session.id),)
    )


async def _active_organization_id(ctx: EndpointContext) -> str | None:
    row = await _session_row(ctx)
    if not row:
        return None
    return row.get("activeOrganizationId")


async def _active_team_id(ctx: EndpointContext) -> str | None:
    row = await _session_row(ctx)
    if not row:
        return None
    return row.get("activeTeamId")


# ---------------------------------------------------------------------------
# Organization CRUD
# ---------------------------------------------------------------------------


async def _create_organization(ctx: EndpointContext) -> dict[str, Any]:
    if ctx.session is None:
        raise APIError(401, "UNAUTHORIZED")
    body: CreateOrganizationBody = ctx.body
    slug = (body.slug or _slugify(body.name)).lower()
    if await _find_slug_collision(ctx, slug):
        raise APIError(409, "SLUG_TAKEN")

    now = _now()
    org = await ctx.auth.adapter.create(
        model="organization",
        data={
            "name": body.name,
            "slug": slug,
            "logo": body.logo,
            "metadata": body.metadata,
            "createdAt": now,
            "updatedAt": now,
        },
    )
    await ctx.auth.adapter.create(
        model="member",
        data={
            "organizationId": org["id"],
            "userId": ctx.session.user_id,
            "role": "owner",
            "createdAt": now,
        },
    )

    if not body.keepCurrentActiveOrganization:
        await _set_active_organization(
            ctx, session_id=ctx.session.id, organization_id=org["id"]
        )

    # Reference TS returns the organization at the top level (no wrapping key)
    # so the JS client can do `result.data.id` directly.
    return org


async def _list_organizations(ctx: EndpointContext) -> list[dict[str, Any]]:
    if ctx.session is None:
        raise APIError(401, "UNAUTHORIZED")
    members = await ctx.auth.adapter.find_many(
        model="member",
        where=(Where(field="userId", value=ctx.session.user_id),),
    )
    if not members:
        return []
    ids = [m["organizationId"] for m in members]
    orgs = await ctx.auth.adapter.find_many(
        model="organization",
        where=(Where(field="id", value=ids, operator="in"),),
    )
    return orgs


async def _get_organization(ctx: EndpointContext) -> dict[str, Any]:
    if ctx.session is None:
        raise APIError(401, "UNAUTHORIZED")
    q = ctx.request.query
    org_id = q.get("organizationId")
    slug = q.get("slug")
    if not org_id and not slug:
        raise APIError(400, "INVALID_REQUEST", message="organizationId or slug required")
    if org_id:
        org = await ctx.auth.adapter.find_one(
            model="organization", where=(Where(field="id", value=org_id),)
        )
    else:
        org = await ctx.auth.adapter.find_one(
            model="organization",
            where=(Where(field="slug", value=str(slug).lower()),),
        )
    if not org:
        raise APIError(404, "ORGANIZATION_NOT_FOUND")
    # Membership: the user must be a member of this org.
    member = await _get_member(
        ctx, organization_id=org["id"], user_id=ctx.session.user_id
    )
    if not member:
        raise APIError(403, "NOT_MEMBER")
    return org


async def _update_organization(ctx: EndpointContext) -> dict[str, Any]:
    body: UpdateOrganizationBody = ctx.body
    await _enforce_permission(
        ctx,
        organization_id=body.organizationId,
        required={"organization": ["update"]},
    )
    update: dict[str, Any] = {"updatedAt": _now()}
    allowed = {"name", "slug", "logo", "metadata"}
    for k, v in body.data.items():
        if k in allowed:
            if k == "slug":
                v = str(v).lower()
                if await _find_slug_collision(ctx, v):
                    raise APIError(409, "SLUG_TAKEN")
            update[k] = v
    row = await ctx.auth.adapter.update(
        model="organization",
        where=(Where(field="id", value=body.organizationId),),
        update=update,
    )
    if row is None:
        raise APIError(404, "ORGANIZATION_NOT_FOUND")
    return row


async def _delete_organization(ctx: EndpointContext) -> dict[str, bool]:
    body: DeleteOrganizationBody = ctx.body
    await _enforce_permission(
        ctx,
        organization_id=body.organizationId,
        required={"organization": ["delete"]},
    )
    # Cascade: members, invitations, teams, teamMembers, organizationRole rows.
    where = (Where(field="organizationId", value=body.organizationId),)
    await ctx.auth.adapter.delete_many(model="member", where=where)
    await ctx.auth.adapter.delete_many(model="invitation", where=where)
    if _options(ctx).get("teams_enabled"):
        team_rows = await ctx.auth.adapter.find_many(model="team", where=where)
        for t in team_rows:
            await ctx.auth.adapter.delete_many(
                model="teamMember",
                where=(Where(field="teamId", value=t["id"]),),
            )
        await ctx.auth.adapter.delete_many(model="team", where=where)
    if _options(ctx).get("dynamic_access_control_enabled"):
        await ctx.auth.adapter.delete_many(model="organizationRole", where=where)
    await ctx.auth.adapter.delete(
        model="organization",
        where=(Where(field="id", value=body.organizationId),),
    )
    # Clear active org on any sessions pointing at this org.
    sessions = await ctx.auth.adapter.find_many(
        model="session",
        where=(Where(field="activeOrganizationId", value=body.organizationId),),
    )
    for s in sessions:
        await _set_active_organization(
            ctx, session_id=s["id"], organization_id=None
        )
    return {"success": True}


async def _set_active(ctx: EndpointContext) -> dict[str, Any]:
    if ctx.session is None:
        raise APIError(401, "UNAUTHORIZED")
    body: SetActiveOrganizationBody = ctx.body
    if body.organizationId is None:
        await _set_active_organization(
            ctx, session_id=ctx.session.id, organization_id=None
        )
        return {"success": True, "activeOrganizationId": None}
    # Ensure caller is a member.
    member = await _get_member(
        ctx,
        organization_id=body.organizationId,
        user_id=ctx.session.user_id,
    )
    if not member:
        raise APIError(403, "NOT_MEMBER")
    await _set_active_organization(
        ctx, session_id=ctx.session.id, organization_id=body.organizationId
    )
    return {"success": True, "activeOrganizationId": body.organizationId}


# ---------------------------------------------------------------------------
# Invitations
# ---------------------------------------------------------------------------


def _invitation_expiry(ctx: EndpointContext) -> int:
    seconds = _options(ctx).get("invitation_expires_in", 60 * 60 * 24 * 2)
    return _now() + int(seconds)


async def _invite_member(ctx: EndpointContext) -> dict[str, Any]:
    body: InviteMemberBody = ctx.body
    await _enforce_permission(
        ctx,
        organization_id=body.organizationId,
        required={"invitation": ["create"]},
    )

    role_table = await _resolve_role_table(ctx, body.organizationId)
    if body.role not in role_table:
        raise APIError(400, "ROLE_NOT_FOUND")

    # Duplicate pending invite check.
    existing = await ctx.auth.adapter.find_one(
        model="invitation",
        where=(
            Where(field="organizationId", value=body.organizationId),
            Where(field="email", value=body.email),
            Where(field="status", value="pending"),
        ),
    )
    if existing:
        raise APIError(409, "EMAIL_ALREADY_INVITED")

    # Already-a-member check.
    user = await ctx.auth.adapter.find_one(
        model="user", where=(Where(field="email", value=body.email),)
    )
    if user is not None:
        existing_member = await _get_member(
            ctx, organization_id=body.organizationId, user_id=user["id"]
        )
        if existing_member:
            raise APIError(409, "ALREADY_MEMBER")

    invite = await ctx.auth.adapter.create(
        model="invitation",
        data={
            "organizationId": body.organizationId,
            "email": body.email,
            "role": body.role,
            "status": "pending",
            "inviterId": ctx.session.user_id if ctx.session else None,
            "expiresAt": _invitation_expiry(ctx),
            "createdAt": _now(),
        },
    )

    # Fire the user-supplied send hook, if any.
    options = _options(ctx)
    sender = options.get("send_invitation")
    if sender is not None:
        org = await ctx.auth.adapter.find_one(
            model="organization",
            where=(Where(field="id", value=body.organizationId),),
        )
        await sender(
            {
                "email": body.email,
                "invitation": invite,
                "organization": org,
                "inviterId": ctx.session.user_id if ctx.session else None,
            }
        )

    return {"invitation": invite}


async def _cancel_invitation(ctx: EndpointContext) -> dict[str, bool]:
    body: CancelInvitationBody = ctx.body
    invite = await ctx.auth.adapter.find_one(
        model="invitation",
        where=(Where(field="id", value=body.invitationId),),
    )
    if not invite:
        raise APIError(404, "INVITATION_NOT_FOUND")
    await _enforce_permission(
        ctx,
        organization_id=invite["organizationId"],
        required={"invitation": ["cancel"]},
    )
    await ctx.auth.adapter.update(
        model="invitation",
        where=(Where(field="id", value=body.invitationId),),
        update={"status": "cancelled"},
    )
    return {"success": True}


async def _accept_invitation(ctx: EndpointContext) -> dict[str, Any]:
    if ctx.session is None:
        raise APIError(401, "UNAUTHORIZED")
    body: AcceptInvitationBody = ctx.body
    invite = await ctx.auth.adapter.find_one(
        model="invitation",
        where=(Where(field="id", value=body.invitationId),),
    )
    if not invite:
        raise APIError(404, "INVITATION_NOT_FOUND")
    if invite["status"] != "pending":
        raise APIError(400, "INVITATION_NOT_FOUND", message="Invitation is not pending")
    expires_at = int(invite.get("expiresAt") or 0)
    if expires_at and expires_at < _now():
        await ctx.auth.adapter.update(
            model="invitation",
            where=(Where(field="id", value=invite["id"]),),
            update={"status": "expired"},
        )
        raise APIError(400, "INVITATION_EXPIRED")

    user = await ctx.auth.adapter.find_one(
        model="user",
        where=(Where(field="id", value=ctx.session.user_id),),
    )
    if not user or user.get("email", "").lower() != invite["email"].lower():
        raise APIError(403, "INVITATION_NOT_FOR_YOU")

    # Idempotency: skip if already a member.
    existing_member = await _get_member(
        ctx,
        organization_id=invite["organizationId"],
        user_id=ctx.session.user_id,
    )
    if existing_member:
        member = existing_member
        newly_added = False
    else:
        member = await ctx.auth.adapter.create(
            model="member",
            data={
                "organizationId": invite["organizationId"],
                "userId": ctx.session.user_id,
                "role": invite["role"],
                "createdAt": _now(),
            },
        )
        newly_added = True

    await ctx.auth.adapter.update(
        model="invitation",
        where=(Where(field="id", value=invite["id"]),),
        update={"status": "accepted"},
    )
    if newly_added:
        await get_bus(ctx.auth).emit(
            "organization.member.added",
            MemberEvent(
                organization_id=invite["organizationId"],
                user_id=ctx.session.user_id,
                role=invite["role"],
                action="added",
            ),
        )
    return {"member": member, "invitation": {**invite, "status": "accepted"}}


async def _reject_invitation(ctx: EndpointContext) -> dict[str, bool]:
    if ctx.session is None:
        raise APIError(401, "UNAUTHORIZED")
    body: RejectInvitationBody = ctx.body
    invite = await ctx.auth.adapter.find_one(
        model="invitation",
        where=(Where(field="id", value=body.invitationId),),
    )
    if not invite:
        raise APIError(404, "INVITATION_NOT_FOUND")
    user = await ctx.auth.adapter.find_one(
        model="user", where=(Where(field="id", value=ctx.session.user_id),)
    )
    if not user or user.get("email", "").lower() != invite["email"].lower():
        raise APIError(403, "INVITATION_NOT_FOR_YOU")
    await ctx.auth.adapter.update(
        model="invitation",
        where=(Where(field="id", value=body.invitationId),),
        update={"status": "rejected"},
    )
    return {"success": True}


async def _list_invitations(ctx: EndpointContext) -> list[dict[str, Any]]:
    if ctx.session is None:
        raise APIError(401, "UNAUTHORIZED")
    user = await ctx.auth.adapter.find_one(
        model="user", where=(Where(field="id", value=ctx.session.user_id),)
    )
    if not user:
        return []
    rows = await ctx.auth.adapter.find_many(
        model="invitation",
        where=(
            Where(field="email", value=user["email"]),
            Where(field="status", value="pending"),
        ),
    )
    return rows


# ---------------------------------------------------------------------------
# Members
# ---------------------------------------------------------------------------


async def _list_members(ctx: EndpointContext) -> list[dict[str, Any]]:
    if ctx.session is None:
        raise APIError(401, "UNAUTHORIZED")
    organization_id = ctx.request.query.get("organizationId")
    if not organization_id:
        raise APIError(400, "INVALID_REQUEST", message="organizationId required")
    member = await _get_member(
        ctx, organization_id=organization_id, user_id=ctx.session.user_id
    )
    if not member:
        raise APIError(403, "NOT_MEMBER")
    return await ctx.auth.adapter.find_many(
        model="member",
        where=(Where(field="organizationId", value=organization_id),),
    )


async def _remove_member(ctx: EndpointContext) -> dict[str, bool]:
    body: RemoveMemberBody = ctx.body
    caller = await _require_caller_member(ctx, body.organizationId)
    await _enforce_permission(
        ctx,
        organization_id=body.organizationId,
        required={"member": ["delete"]},
        member=caller,
    )
    # Find target by member id or by user email.
    target: dict[str, Any] | None = None
    if "@" in body.memberIdOrEmail:
        user = await ctx.auth.adapter.find_one(
            model="user", where=(Where(field="email", value=body.memberIdOrEmail),)
        )
        if user:
            target = await _get_member(
                ctx, organization_id=body.organizationId, user_id=user["id"]
            )
    else:
        target = await ctx.auth.adapter.find_one(
            model="member",
            where=(
                Where(field="id", value=body.memberIdOrEmail),
                Where(field="organizationId", value=body.organizationId),
            ),
        )
    if not target:
        raise APIError(404, "MEMBER_NOT_FOUND")
    # Can't remove the last owner.
    if target["role"] == "owner":
        if await _count_owners(ctx, body.organizationId) <= 1:
            raise APIError(400, "LAST_OWNER")
    await ctx.auth.adapter.delete(
        model="member",
        where=(Where(field="id", value=target["id"]),),
    )
    await get_bus(ctx.auth).emit(
        "organization.member.removed",
        MemberEvent(
            organization_id=body.organizationId,
            user_id=target["userId"],
            role=target["role"],
            action="removed",
        ),
    )
    return {"success": True}


async def _update_member_role(ctx: EndpointContext) -> dict[str, Any]:
    body: UpdateMemberRoleBody = ctx.body
    caller = await _require_caller_member(ctx, body.organizationId)
    # Only owners may change member roles.
    if caller["role"] != "owner":
        raise APIError(403, "NOT_ALLOWED")
    target = await ctx.auth.adapter.find_one(
        model="member",
        where=(
            Where(field="id", value=body.memberId),
            Where(field="organizationId", value=body.organizationId),
        ),
    )
    if not target:
        raise APIError(404, "MEMBER_NOT_FOUND")
    role_table = await _resolve_role_table(ctx, body.organizationId)
    if body.role not in role_table:
        raise APIError(400, "ROLE_NOT_FOUND")
    # Demoting the last owner is not allowed.
    if target["role"] == "owner" and body.role != "owner":
        if await _count_owners(ctx, body.organizationId) <= 1:
            raise APIError(400, "LAST_OWNER")
    row = await ctx.auth.adapter.update(
        model="member",
        where=(Where(field="id", value=body.memberId),),
        update={"role": body.role},
    )
    await get_bus(ctx.auth).emit(
        "organization.member.updated",
        MemberEvent(
            organization_id=body.organizationId,
            user_id=target["userId"],
            role=body.role,
            action="updated",
        ),
    )
    return {"member": row}


async def _leave_organization(ctx: EndpointContext) -> dict[str, bool]:
    if ctx.session is None:
        raise APIError(401, "UNAUTHORIZED")
    body: LeaveOrganizationBody = ctx.body
    member = await _get_member(
        ctx, organization_id=body.organizationId, user_id=ctx.session.user_id
    )
    if not member:
        raise APIError(403, "NOT_MEMBER")
    if member["role"] == "owner":
        if await _count_owners(ctx, body.organizationId) <= 1:
            raise APIError(400, "LAST_OWNER")
    await ctx.auth.adapter.delete(
        model="member",
        where=(Where(field="id", value=member["id"]),),
    )
    await get_bus(ctx.auth).emit(
        "organization.member.removed",
        MemberEvent(
            organization_id=body.organizationId,
            user_id=ctx.session.user_id,
            role=member["role"],
            action="removed",
        ),
    )
    # If this org was active, clear it on the session.
    session_row = await ctx.auth.adapter.find_one(
        model="session", where=(Where(field="id", value=ctx.session.id),)
    )
    if session_row and session_row.get("activeOrganizationId") == body.organizationId:
        await _set_active_organization(
            ctx, session_id=ctx.session.id, organization_id=None
        )
    return {"success": True}


# ---------------------------------------------------------------------------
# Permissions
# ---------------------------------------------------------------------------


async def _has_permission(ctx: EndpointContext) -> dict[str, bool]:
    body: HasPermissionBody = ctx.body
    caller = await _require_caller_member(ctx, body.organizationId)
    role_table = await _resolve_role_table(ctx, body.organizationId)
    allowed = has_permission(caller["role"], body.permissions, role_table)
    return {"allowed": allowed}


# ---------------------------------------------------------------------------
# Teams (gated by options.teams_enabled)
# ---------------------------------------------------------------------------


def _require_teams_enabled(ctx: EndpointContext) -> None:
    if not _options(ctx).get("teams_enabled"):
        raise APIError(404, "TEAMS_DISABLED")


async def _create_team(ctx: EndpointContext) -> dict[str, Any]:
    _require_teams_enabled(ctx)
    body: CreateTeamBody = ctx.body
    await _enforce_permission(
        ctx,
        organization_id=body.organizationId,
        required={"team": ["create"]},
    )
    existing = await ctx.auth.adapter.find_one(
        model="team",
        where=(
            Where(field="organizationId", value=body.organizationId),
            Where(field="name", value=body.name),
        ),
    )
    if existing:
        raise APIError(409, "TEAM_ALREADY_EXISTS")
    now = _now()
    team = await ctx.auth.adapter.create(
        model="team",
        data={
            "name": body.name,
            "organizationId": body.organizationId,
            "createdAt": now,
            "updatedAt": now,
        },
    )
    return {"team": team}


async def _update_team(ctx: EndpointContext) -> dict[str, Any]:
    _require_teams_enabled(ctx)
    body: UpdateTeamBody = ctx.body
    await _enforce_permission(
        ctx,
        organization_id=body.organizationId,
        required={"team": ["update"]},
    )
    row = await ctx.auth.adapter.update(
        model="team",
        where=(
            Where(field="id", value=body.teamId),
            Where(field="organizationId", value=body.organizationId),
        ),
        update={"name": body.name, "updatedAt": _now()},
    )
    if not row:
        raise APIError(404, "TEAM_NOT_FOUND")
    return {"team": row}


async def _delete_team(ctx: EndpointContext) -> dict[str, bool]:
    _require_teams_enabled(ctx)
    body: DeleteTeamBody = ctx.body
    await _enforce_permission(
        ctx,
        organization_id=body.organizationId,
        required={"team": ["delete"]},
    )
    await ctx.auth.adapter.delete_many(
        model="teamMember",
        where=(Where(field="teamId", value=body.teamId),),
    )
    await ctx.auth.adapter.delete(
        model="team",
        where=(
            Where(field="id", value=body.teamId),
            Where(field="organizationId", value=body.organizationId),
        ),
    )
    return {"success": True}


async def _add_team_member(ctx: EndpointContext) -> dict[str, Any]:
    _require_teams_enabled(ctx)
    body: AddTeamMemberBody = ctx.body
    await _enforce_permission(
        ctx,
        organization_id=body.organizationId,
        required={"team": ["update"]},
    )
    team = await ctx.auth.adapter.find_one(
        model="team",
        where=(
            Where(field="id", value=body.teamId),
            Where(field="organizationId", value=body.organizationId),
        ),
    )
    if not team:
        raise APIError(404, "TEAM_NOT_FOUND")
    # Target user must be a member of the org.
    target_member = await _get_member(
        ctx, organization_id=body.organizationId, user_id=body.userId
    )
    if not target_member:
        raise APIError(404, "MEMBER_NOT_FOUND")
    row = await ctx.auth.adapter.create(
        model="teamMember",
        data={
            "teamId": body.teamId,
            "userId": body.userId,
            "createdAt": _now(),
        },
    )
    return {"teamMember": row}


async def _remove_team_member(ctx: EndpointContext) -> dict[str, bool]:
    _require_teams_enabled(ctx)
    body: RemoveTeamMemberBody = ctx.body
    await _enforce_permission(
        ctx,
        organization_id=body.organizationId,
        required={"team": ["update"]},
    )
    await ctx.auth.adapter.delete_many(
        model="teamMember",
        where=(
            Where(field="teamId", value=body.teamId),
            Where(field="userId", value=body.userId),
        ),
    )
    return {"success": True}


async def _list_teams(ctx: EndpointContext) -> list[dict[str, Any]]:
    _require_teams_enabled(ctx)
    if ctx.session is None:
        raise APIError(401, "UNAUTHORIZED")
    organization_id = ctx.request.query.get("organizationId")
    if not organization_id:
        raise APIError(400, "INVALID_REQUEST", message="organizationId required")
    member = await _get_member(
        ctx, organization_id=organization_id, user_id=ctx.session.user_id
    )
    if not member:
        raise APIError(403, "NOT_MEMBER")
    return await ctx.auth.adapter.find_many(
        model="team",
        where=(Where(field="organizationId", value=organization_id),),
    )


# ---------------------------------------------------------------------------
# Dynamic Access Control roles
# ---------------------------------------------------------------------------


def _require_dynamic_ac(ctx: EndpointContext) -> None:
    if not _options(ctx).get("dynamic_access_control_enabled"):
        raise APIError(404, "DYNAMIC_AC_DISABLED")


def _validate_resources(permissions: dict[str, list[str]]) -> None:
    for resource in permissions:
        if resource not in DEFAULT_STATEMENTS:
            raise APIError(400, "INVALID_RESOURCE", message=f"Unknown resource: {resource}")


async def _create_role(ctx: EndpointContext) -> dict[str, Any]:
    _require_dynamic_ac(ctx)
    body: CreateRoleBody = ctx.body
    await _enforce_permission(
        ctx,
        organization_id=body.organizationId,
        required={"ac": ["create"]},
    )
    _validate_resources(body.permissions)
    if body.role in DEFAULT_ROLES:
        raise APIError(409, "ROLE_ALREADY_EXISTS")
    existing = await ctx.auth.adapter.find_one(
        model="organizationRole",
        where=(
            Where(field="organizationId", value=body.organizationId),
            Where(field="role", value=body.role),
        ),
    )
    if existing:
        raise APIError(409, "ROLE_ALREADY_EXISTS")
    row = await ctx.auth.adapter.create(
        model="organizationRole",
        data={
            "organizationId": body.organizationId,
            "role": body.role,
            "permissions": body.permissions,
            "createdAt": _now(),
            "updatedAt": _now(),
        },
    )
    return {"role": row}


async def _update_role(ctx: EndpointContext) -> dict[str, Any]:
    _require_dynamic_ac(ctx)
    body: UpdateRoleBody = ctx.body
    await _enforce_permission(
        ctx,
        organization_id=body.organizationId,
        required={"ac": ["update"]},
    )
    _validate_resources(body.permissions)
    row = await ctx.auth.adapter.update(
        model="organizationRole",
        where=(
            Where(field="organizationId", value=body.organizationId),
            Where(field="role", value=body.role),
        ),
        update={"permissions": body.permissions, "updatedAt": _now()},
    )
    if not row:
        raise APIError(404, "ROLE_NOT_FOUND")
    return {"role": row}


async def _delete_role(ctx: EndpointContext) -> dict[str, bool]:
    _require_dynamic_ac(ctx)
    body: DeleteRoleBody = ctx.body
    await _enforce_permission(
        ctx,
        organization_id=body.organizationId,
        required={"ac": ["delete"]},
    )
    if body.role in DEFAULT_ROLES:
        raise APIError(403, "NOT_ALLOWED", message="Cannot delete a built-in role")
    await ctx.auth.adapter.delete(
        model="organizationRole",
        where=(
            Where(field="organizationId", value=body.organizationId),
            Where(field="role", value=body.role),
        ),
    )
    return {"success": True}


async def _list_roles(ctx: EndpointContext) -> list[dict[str, Any]]:
    _require_dynamic_ac(ctx)
    if ctx.session is None:
        raise APIError(401, "UNAUTHORIZED")
    organization_id = ctx.request.query.get("organizationId")
    if not organization_id:
        raise APIError(400, "INVALID_REQUEST", message="organizationId required")
    member = await _get_member(
        ctx, organization_id=organization_id, user_id=ctx.session.user_id
    )
    if not member:
        raise APIError(403, "NOT_MEMBER")
    rows = await ctx.auth.adapter.find_many(
        model="organizationRole",
        where=(Where(field="organizationId", value=organization_id),),
    )
    # Surface built-ins too for client convenience.
    builtins = [
        {"role": name, "permissions": dict(role.statement), "builtin": True}
        for name, role in DEFAULT_ROLES.items()
    ]
    return [*builtins, *rows]


# ---------------------------------------------------------------------------
# Additional read / lookup endpoints (parity with upstream)
# ---------------------------------------------------------------------------


async def _check_slug(ctx: EndpointContext) -> dict[str, bool]:
    if ctx.session is None:
        raise APIError(401, "UNAUTHORIZED")
    body: CheckSlugBody = ctx.body
    if await _find_slug_collision(ctx, body.slug):
        raise APIError(400, "SLUG_TAKEN")
    return {"status": True}


async def _resolve_org_id_from_query(
    ctx: EndpointContext, *, allow_active: bool = True
) -> str | None:
    """Resolve an organization id from query params, with slug lookup,
    falling back to the session's active organization."""
    q = ctx.request.query
    slug = q.get("organizationSlug")
    if slug:
        org = await ctx.auth.adapter.find_one(
            model="organization",
            where=(Where(field="slug", value=str(slug).lower()),),
        )
        if not org:
            raise APIError(400, "ORGANIZATION_NOT_FOUND")
        return org["id"]
    org_id = q.get("organizationId")
    if org_id:
        return str(org_id)
    if allow_active:
        return await _active_organization_id(ctx)
    return None


async def _get_full_organization(ctx: EndpointContext) -> dict[str, Any] | None:
    if ctx.session is None:
        raise APIError(401, "UNAUTHORIZED")
    organization_id = await _resolve_org_id_from_query(ctx)
    if not organization_id:
        return None
    org = await ctx.auth.adapter.find_one(
        model="organization", where=(Where(field="id", value=organization_id),)
    )
    if not org:
        raise APIError(400, "ORGANIZATION_NOT_FOUND")
    member = await _get_member(
        ctx, organization_id=org["id"], user_id=ctx.session.user_id
    )
    if not member:
        # Clear active org pointer (mirrors upstream) then 403.
        await _set_active_organization(
            ctx, session_id=ctx.session.id, organization_id=None
        )
        raise APIError(403, "NOT_MEMBER")
    where = (Where(field="organizationId", value=org["id"]),)
    members = await ctx.auth.adapter.find_many(model="member", where=where)
    invitations = await ctx.auth.adapter.find_many(model="invitation", where=where)
    result: dict[str, Any] = {
        **org,
        "members": members,
        "invitations": invitations,
    }
    if _options(ctx).get("teams_enabled"):
        result["teams"] = await ctx.auth.adapter.find_many(model="team", where=where)
    return result


async def _get_active_member(ctx: EndpointContext) -> dict[str, Any]:
    if ctx.session is None:
        raise APIError(401, "UNAUTHORIZED")
    organization_id = await _active_organization_id(ctx)
    if not organization_id:
        raise APIError(400, "NO_ACTIVE_ORGANIZATION")
    member = await _get_member(
        ctx, organization_id=organization_id, user_id=ctx.session.user_id
    )
    if not member:
        raise APIError(400, "MEMBER_NOT_FOUND")
    return member


async def _get_active_member_role(ctx: EndpointContext) -> dict[str, Any]:
    if ctx.session is None:
        raise APIError(401, "UNAUTHORIZED")
    organization_id = await _resolve_org_id_from_query(ctx)
    if not organization_id:
        raise APIError(400, "NO_ACTIVE_ORGANIZATION")
    target_user = ctx.request.query.get("userId") or ctx.session.user_id
    caller = await _get_member(
        ctx, organization_id=organization_id, user_id=ctx.session.user_id
    )
    if not caller:
        raise APIError(403, "NOT_MEMBER")
    member = (
        caller
        if target_user == ctx.session.user_id
        else await _get_member(
            ctx, organization_id=organization_id, user_id=str(target_user)
        )
    )
    if not member:
        raise APIError(400, "MEMBER_NOT_FOUND")
    return {"role": member["role"]}


async def _get_invitation(ctx: EndpointContext) -> dict[str, Any]:
    if ctx.session is None:
        raise APIError(401, "UNAUTHORIZED")
    invitation_id = ctx.request.query.get("id")
    if not invitation_id:
        raise APIError(400, "INVALID_REQUEST", message="id required")
    invitation = await ctx.auth.adapter.find_one(
        model="invitation", where=(Where(field="id", value=invitation_id),)
    )
    expires_at = invitation.get("expiresAt") if invitation else None
    if (
        not invitation
        or invitation.get("status") != "pending"
        or (expires_at is not None and int(expires_at) < _now())
    ):
        raise APIError(400, "INVITATION_NOT_FOUND")
    user = await ctx.auth.adapter.find_one(
        model="user", where=(Where(field="id", value=ctx.session.user_id),)
    )
    if not user or str(invitation["email"]).lower() != str(user["email"]).lower():
        raise APIError(403, "NOT_INVITATION_RECIPIENT")
    org = await ctx.auth.adapter.find_one(
        model="organization",
        where=(Where(field="id", value=invitation["organizationId"]),),
    )
    if not org:
        raise APIError(400, "ORGANIZATION_NOT_FOUND")
    inviter = await ctx.auth.adapter.find_one(
        model="user", where=(Where(field="id", value=invitation["inviterId"]),)
    )
    return {
        **invitation,
        "organizationName": org["name"],
        "organizationSlug": org["slug"],
        "inviterEmail": inviter["email"] if inviter else None,
    }


async def _list_user_invitations(ctx: EndpointContext) -> list[dict[str, Any]]:
    # Same shape as _list_invitations (invites addressed to the caller's email).
    return await _list_invitations(ctx)


async def _get_role(ctx: EndpointContext) -> dict[str, Any]:
    _require_dynamic_ac(ctx)
    if ctx.session is None:
        raise APIError(401, "UNAUTHORIZED")
    organization_id = await _resolve_org_id_from_query(ctx)
    if not organization_id:
        raise APIError(400, "NO_ACTIVE_ORGANIZATION")
    await _enforce_permission(
        ctx, organization_id=organization_id, required={"ac": ["read"]}
    )
    role_name = ctx.request.query.get("roleName")
    role_id = ctx.request.query.get("roleId")
    if role_id:
        row = await ctx.auth.adapter.find_one(
            model="organizationRole",
            where=(
                Where(field="id", value=role_id),
                Where(field="organizationId", value=organization_id),
            ),
        )
    elif role_name:
        row = await ctx.auth.adapter.find_one(
            model="organizationRole",
            where=(
                Where(field="role", value=role_name),
                Where(field="organizationId", value=organization_id),
            ),
        )
    else:
        raise APIError(400, "INVALID_REQUEST", message="roleName or roleId required")
    if not row:
        raise APIError(404, "ROLE_NOT_FOUND")
    return {"role": row}


async def _set_active_team_endpoint(ctx: EndpointContext) -> dict[str, Any] | None:
    _require_teams_enabled(ctx)
    if ctx.session is None:
        raise APIError(401, "UNAUTHORIZED")
    body: SetActiveTeamBody = ctx.body
    if body.teamId is None:
        await _set_active_team(ctx, session_id=ctx.session.id, team_id=None)
        return None
    active_org = await _active_organization_id(ctx)
    if not active_org:
        raise APIError(400, "NO_ACTIVE_ORGANIZATION")
    team = await ctx.auth.adapter.find_one(
        model="team",
        where=(
            Where(field="id", value=body.teamId),
            Where(field="organizationId", value=active_org),
        ),
    )
    if not team:
        raise APIError(400, "TEAM_NOT_FOUND")
    membership = await ctx.auth.adapter.find_one(
        model="teamMember",
        where=(
            Where(field="teamId", value=body.teamId),
            Where(field="userId", value=ctx.session.user_id),
        ),
    )
    if not membership:
        raise APIError(403, "NOT_TEAM_MEMBER")
    await _set_active_team(ctx, session_id=ctx.session.id, team_id=team["id"])
    return team


async def _list_user_teams(ctx: EndpointContext) -> list[dict[str, Any]]:
    _require_teams_enabled(ctx)
    if ctx.session is None:
        raise APIError(401, "UNAUTHORIZED")
    memberships = await ctx.auth.adapter.find_many(
        model="teamMember",
        where=(Where(field="userId", value=ctx.session.user_id),),
    )
    if not memberships:
        return []
    team_ids = [m["teamId"] for m in memberships]
    return await ctx.auth.adapter.find_many(
        model="team", where=(Where(field="id", value=team_ids, operator="in"),)
    )


async def _list_team_members(ctx: EndpointContext) -> list[dict[str, Any]]:
    _require_teams_enabled(ctx)
    if ctx.session is None:
        raise APIError(401, "UNAUTHORIZED")
    team_id = ctx.request.query.get("teamId") or await _active_team_id(ctx)
    if not team_id:
        raise APIError(400, "NO_ACTIVE_TEAM")
    membership = await ctx.auth.adapter.find_one(
        model="teamMember",
        where=(
            Where(field="teamId", value=team_id),
            Where(field="userId", value=ctx.session.user_id),
        ),
    )
    if not membership:
        raise APIError(400, "NOT_TEAM_MEMBER")
    return await ctx.auth.adapter.find_many(
        model="teamMember", where=(Where(field="teamId", value=team_id),)
    )


# ---------------------------------------------------------------------------
# Endpoint table builder
# ---------------------------------------------------------------------------


_BASE: tuple[AuthEndpoint, ...] = (
    create_auth_endpoint(
        "/organization/create",
        EndpointOptions(
            method="POST", body=CreateOrganizationBody, requires_session=True
        ),
        _create_organization,
    ),
    create_auth_endpoint(
        "/organization/list",
        EndpointOptions(method="GET", requires_session=True),
        _list_organizations,
    ),
    create_auth_endpoint(
        "/organization/get",
        EndpointOptions(method="GET", requires_session=True),
        _get_organization,
    ),
    create_auth_endpoint(
        "/organization/update",
        EndpointOptions(
            method="POST", body=UpdateOrganizationBody, requires_session=True
        ),
        _update_organization,
    ),
    create_auth_endpoint(
        "/organization/delete",
        EndpointOptions(
            method="POST", body=DeleteOrganizationBody, requires_session=True
        ),
        _delete_organization,
    ),
    create_auth_endpoint(
        "/organization/set-active",
        EndpointOptions(
            method="POST", body=SetActiveOrganizationBody, requires_session=True
        ),
        _set_active,
    ),
    create_auth_endpoint(
        "/organization/invite-member",
        EndpointOptions(method="POST", body=InviteMemberBody, requires_session=True),
        _invite_member,
    ),
    create_auth_endpoint(
        "/organization/cancel-invitation",
        EndpointOptions(
            method="POST", body=CancelInvitationBody, requires_session=True
        ),
        _cancel_invitation,
    ),
    create_auth_endpoint(
        "/organization/accept-invitation",
        EndpointOptions(
            method="POST", body=AcceptInvitationBody, requires_session=True
        ),
        _accept_invitation,
    ),
    create_auth_endpoint(
        "/organization/reject-invitation",
        EndpointOptions(
            method="POST", body=RejectInvitationBody, requires_session=True
        ),
        _reject_invitation,
    ),
    create_auth_endpoint(
        "/organization/list-invitations",
        EndpointOptions(method="GET", requires_session=True),
        _list_invitations,
    ),
    create_auth_endpoint(
        "/organization/list-members",
        EndpointOptions(method="GET", requires_session=True),
        _list_members,
    ),
    create_auth_endpoint(
        "/organization/remove-member",
        EndpointOptions(method="POST", body=RemoveMemberBody, requires_session=True),
        _remove_member,
    ),
    create_auth_endpoint(
        "/organization/update-member-role",
        EndpointOptions(
            method="POST", body=UpdateMemberRoleBody, requires_session=True
        ),
        _update_member_role,
    ),
    create_auth_endpoint(
        "/organization/leave",
        EndpointOptions(
            method="POST", body=LeaveOrganizationBody, requires_session=True
        ),
        _leave_organization,
    ),
    create_auth_endpoint(
        "/organization/has-permission",
        EndpointOptions(method="POST", body=HasPermissionBody, requires_session=True),
        _has_permission,
    ),
    create_auth_endpoint(
        "/organization/check-slug",
        EndpointOptions(method="POST", body=CheckSlugBody, requires_session=True),
        _check_slug,
    ),
    create_auth_endpoint(
        "/organization/get-full-organization",
        EndpointOptions(method="GET", requires_session=True),
        _get_full_organization,
    ),
    create_auth_endpoint(
        "/organization/get-active-member",
        EndpointOptions(method="GET", requires_session=True),
        _get_active_member,
    ),
    create_auth_endpoint(
        "/organization/get-active-member-role",
        EndpointOptions(method="GET", requires_session=True),
        _get_active_member_role,
    ),
    create_auth_endpoint(
        "/organization/get-invitation",
        EndpointOptions(method="GET", requires_session=True),
        _get_invitation,
    ),
    create_auth_endpoint(
        "/organization/list-user-invitations",
        EndpointOptions(method="GET", requires_session=True),
        _list_user_invitations,
    ),
)


_TEAMS: tuple[AuthEndpoint, ...] = (
    create_auth_endpoint(
        "/organization/create-team",
        EndpointOptions(method="POST", body=CreateTeamBody, requires_session=True),
        _create_team,
    ),
    create_auth_endpoint(
        "/organization/update-team",
        EndpointOptions(method="POST", body=UpdateTeamBody, requires_session=True),
        _update_team,
    ),
    create_auth_endpoint(
        "/organization/remove-team",
        EndpointOptions(method="POST", body=DeleteTeamBody, requires_session=True),
        _delete_team,
    ),
    create_auth_endpoint(
        "/organization/add-team-member",
        EndpointOptions(method="POST", body=AddTeamMemberBody, requires_session=True),
        _add_team_member,
    ),
    create_auth_endpoint(
        "/organization/remove-team-member",
        EndpointOptions(
            method="POST", body=RemoveTeamMemberBody, requires_session=True
        ),
        _remove_team_member,
    ),
    create_auth_endpoint(
        "/organization/list-teams",
        EndpointOptions(method="GET", requires_session=True),
        _list_teams,
    ),
    create_auth_endpoint(
        "/organization/set-active-team",
        EndpointOptions(method="POST", body=SetActiveTeamBody, requires_session=True),
        _set_active_team_endpoint,
    ),
    create_auth_endpoint(
        "/organization/list-user-teams",
        EndpointOptions(method="GET", requires_session=True),
        _list_user_teams,
    ),
    create_auth_endpoint(
        "/organization/list-team-members",
        EndpointOptions(method="GET", requires_session=True),
        _list_team_members,
    ),
)


_DYNAMIC_AC: tuple[AuthEndpoint, ...] = (
    create_auth_endpoint(
        "/organization/create-role",
        EndpointOptions(method="POST", body=CreateRoleBody, requires_session=True),
        _create_role,
    ),
    create_auth_endpoint(
        "/organization/update-role",
        EndpointOptions(method="POST", body=UpdateRoleBody, requires_session=True),
        _update_role,
    ),
    create_auth_endpoint(
        "/organization/delete-role",
        EndpointOptions(method="POST", body=DeleteRoleBody, requires_session=True),
        _delete_role,
    ),
    create_auth_endpoint(
        "/organization/list-roles",
        EndpointOptions(method="GET", requires_session=True),
        _list_roles,
    ),
    create_auth_endpoint(
        "/organization/get-role",
        EndpointOptions(method="GET", requires_session=True),
        _get_role,
    ),
)


def build_endpoints(
    *, teams_enabled: bool = False, dynamic_ac_enabled: bool = False
) -> tuple[AuthEndpoint, ...]:
    """Compose the endpoint tuple based on feature flags."""
    endpoints: list[AuthEndpoint] = list(_BASE)
    if teams_enabled:
        endpoints.extend(_TEAMS)
    if dynamic_ac_enabled:
        endpoints.extend(_DYNAMIC_AC)
    return tuple(endpoints)


__all__ = ["build_endpoints"]
