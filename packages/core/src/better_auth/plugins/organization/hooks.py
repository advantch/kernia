"""Hooks contributed by the organization plugin.

Two responsibilities:

  1. **Membership gate** — every ``/organization/*`` route requires the caller to
     be a member of the target organization. The before-hook resolves the
     ``member`` row once and parks it on ``ctx.plugin_state["org_membership"]`` so
     downstream handlers can read it without a second DB hit. Routes that don't
     yet know the target org (the create endpoint, the global ``/list``, and
     invitation-recipient flows) are passed through.

  2. **Session enrichment** — after ``/get-session`` runs, we look up the active
     organization (if any) and splice ``activeOrganization`` into the response
     body. Mirrors ``orgSessionMiddleware`` in the JS reference.
"""

from __future__ import annotations

from typing import Any, Mapping

from better_auth.error import APIError
from better_auth.types.adapter import Where
from better_auth.types.context import EndpointContext
from better_auth.types.hooks import AfterHook, BeforeHook, PluginHooks


# Routes that don't gate on org-membership at the before-hook layer.
# These either accept membership implicitly (create), list across all of the
# user's orgs (list/list-invitations), or operate on invitations by email
# (accept/reject).
_MEMBERSHIP_EXEMPT_PATHS = frozenset(
    {
        "/organization/create",
        "/organization/list",
        "/organization/list-invitations",
        "/organization/accept-invitation",
        "/organization/reject-invitation",
        "/organization/get-invitation",
    }
)


def _extract_organization_id(ctx: EndpointContext) -> str | None:
    """Pull `organizationId` from body or query, when present."""
    body: Any = ctx.body
    if body is not None:
        # Pydantic v2 model or dataclass.
        if hasattr(body, "organizationId"):
            return getattr(body, "organizationId", None)
        if hasattr(body, "organization_id"):
            return getattr(body, "organization_id", None)
        if isinstance(body, Mapping):
            return body.get("organizationId")
    return ctx.request.query.get("organizationId")  # type: ignore[return-value]


async def _ensure_membership(ctx: EndpointContext) -> None:
    """Before-hook: load member row, reject non-members."""
    if ctx.request.path in _MEMBERSHIP_EXEMPT_PATHS:
        return
    if not ctx.request.path.startswith("/organization/"):
        return
    if ctx.session is None:
        raise APIError(401, "UNAUTHORIZED")

    organization_id = _extract_organization_id(ctx)
    if organization_id is None:
        # Some endpoints (e.g. cancel-invitation) work by invitation id;
        # the handler enforces membership itself.
        return

    member = await ctx.auth.adapter.find_one(
        model="member",
        where=(
            Where(field="organizationId", value=organization_id),
            Where(field="userId", value=ctx.session.user_id),
        ),
    )
    if member is None:
        raise APIError(403, "NOT_MEMBER")
    ctx.auth.plugin_state.setdefault("organization", {})
    # Per-request state lives on EndpointContext via the auth plugin_state mapping;
    # use a per-request key under a request-scoped dict to avoid bleed between
    # concurrent requests. We use id(ctx) so two concurrent requests don't trample.
    bag = ctx.auth.plugin_state["organization"].setdefault("_req", {})
    bag[id(ctx)] = {"member": member, "organizationId": organization_id}


def _get_request_membership(ctx: EndpointContext) -> dict[str, Any] | None:
    bag = (
        ctx.auth.plugin_state.get("organization", {})
        .get("_req", {})
        .get(id(ctx))
    )
    return bag


async def _attach_active_organization(
    ctx: EndpointContext, result: object
) -> object | None:
    """After-hook on `/get-session`: enrich the response with `activeOrganization`.

    Only runs when the handler returned a session (non-null).
    """
    if not isinstance(result, dict):
        return None
    if ctx.session is None:
        return None
    # Look up the session row to get activeOrganizationId.
    session_row = await ctx.auth.adapter.find_one(
        model="session",
        where=(Where(field="id", value=ctx.session.id),),
    )
    if not session_row:
        return None
    active_id = session_row.get("activeOrganizationId")
    if not active_id:
        return None
    org = await ctx.auth.adapter.find_one(
        model="organization",
        where=(Where(field="id", value=active_id),),
    )
    if not org:
        return None
    out = dict(result)
    out["activeOrganization"] = {
        "id": org["id"],
        "name": org["name"],
        "slug": org["slug"],
    }
    return out


def build_hooks() -> PluginHooks:
    """Construct the plugin's :class:`PluginHooks` value."""
    return PluginHooks(
        before=(
            BeforeHook(match="/organization/*", handler=_ensure_membership),
        ),
        after=(
            AfterHook(match="/get-session", handler=_attach_active_organization),
        ),
    )


__all__ = ["build_hooks", "_get_request_membership"]
