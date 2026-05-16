"""Organization plugin constructor.

This file is the *only* public entry point — :func:`organization` returns a
:class:`BetterAuthPlugin` bundling the schema, endpoints, hooks, and error codes
declared in this package.

Feature flags
=============

The plugin accepts a small set of keyword toggles:

* ``teams`` — register team CRUD + the optional ``team``/``teamMember`` tables.
* ``dynamic_access_control`` — register the ``/create-role`` family and the
  ``organizationRole`` table.
* ``invitation_expires_in`` — TTL for fresh invitations, in seconds.
* ``send_invitation`` — async callable invoked with the invitation row + org
  row when an invite is created. Tests pass ``MockSMTP().send`` equivalents
  through this slot.

The flags are also written to ``options.advanced["organization"]`` so the route
handlers can read them at request time.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from better_auth.plugins.organization import hooks as _hooks
from better_auth.plugins.organization import routes as _routes
from better_auth.plugins.organization import schema as _schema
from better_auth.plugins.organization.errors import ORGANIZATION_ERROR_CODES
from better_auth.types.context import AuthContext
from better_auth.types.endpoint import AuthEndpoint
from better_auth.types.hooks import PluginHooks
from better_auth.types.plugin import (
    BetterAuthPlugin,
    InitResult,
    PluginSchema,
    RateLimitRule,
)


SendInvitation = Callable[[Mapping[str, Any]], Awaitable[None]]


@dataclass(frozen=True, slots=True)
class _OrganizationPlugin:
    id: str = "organization"
    version: str | None = "1.0.0"
    schema: PluginSchema | None = None
    endpoints: tuple[AuthEndpoint, ...] = ()
    middlewares: None = None
    hooks: PluginHooks | None = None
    on_request: None = None
    on_response: None = None
    rate_limit: tuple[RateLimitRule, ...] = (
        RateLimitRule(path="/organization/create", window=60, max=10),
        RateLimitRule(path="/organization/invite-member", window=60, max=20),
        RateLimitRule(path="/organization/accept-invitation", window=60, max=20),
    )
    error_codes: Mapping[str, str] = field(
        default_factory=lambda: dict(ORGANIZATION_ERROR_CODES)
    )
    init: Callable[[AuthContext], Awaitable[InitResult | None]] | None = None
    # Stash the constructor args so init can mirror them onto options.advanced.
    _config: Mapping[str, Any] = field(default_factory=dict)


def organization(
    *,
    teams: bool = False,
    dynamic_access_control: bool = False,
    invitation_expires_in: int = 60 * 60 * 24 * 2,
    send_invitation: SendInvitation | None = None,
) -> BetterAuthPlugin:
    """Build the organization plugin.

    The plugin registers:

      * 16 base endpoints (org CRUD, members, invitations, has-permission)
      * 6 team endpoints if ``teams`` is True
      * 4 dynamic-AC role endpoints if ``dynamic_access_control`` is True

    Side effects on init:

      * Writes feature flags + ``send_invitation`` to
        ``options.advanced["organization"]`` so handlers can resolve them.
    """
    config: dict[str, Any] = {
        "teams_enabled": teams,
        "dynamic_access_control_enabled": dynamic_access_control,
        "invitation_expires_in": invitation_expires_in,
        "send_invitation": send_invitation,
    }

    plugin_schema = _schema.build_schema(
        teams_enabled=teams, dynamic_ac_enabled=dynamic_access_control
    )
    endpoints = _routes.build_endpoints(
        teams_enabled=teams, dynamic_ac_enabled=dynamic_access_control
    )

    async def _init(ctx: AuthContext) -> InitResult | None:
        # Merge config into options.advanced["organization"] so route handlers
        # can read it on every request. Preserve any user overrides.
        existing = ctx.options.advanced.get("organization") or {}
        merged = {**config, **existing} if isinstance(existing, dict) else dict(config)
        # send_invitation comes from the constructor; let an explicit override
        # in options.advanced win (matches better-auth precedence).
        if isinstance(existing, dict) and existing.get("send_invitation") is None:
            merged["send_invitation"] = config["send_invitation"]
        ctx.options.advanced["organization"] = merged
        return None

    return _OrganizationPlugin(  # type: ignore[return-value]
        schema=plugin_schema,
        endpoints=endpoints,
        hooks=_hooks.build_hooks(),
        init=_init,
        _config=config,
    )


__all__ = ["SendInvitation", "organization"]
