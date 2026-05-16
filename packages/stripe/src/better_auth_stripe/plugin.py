"""Stripe plugin construction.

Mirrors `reference/packages/stripe/src/index.ts`. The plugin assembles its
endpoints (checkout-session, billing-portal, cancel, resume, list, webhook),
contributes the `subscription` table + `user.stripeCustomerId` column, and
declares its error codes.

The webhook endpoint is exempt from CSRF / trusted-origin checks — that is the
caller's job in production deployment (the user should set `disable_csrf_check`
in `advanced` if Stripe calls the webhook directly, which is the documented
deployment). For the test harness, `ASGIDriver` doesn't send Origin headers so
trusted-origin doesn't trigger.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from better_auth.types.endpoint import AuthEndpoint
from better_auth.types.plugin import BetterAuthPlugin, PluginSchema
from better_auth_stripe.routes import build_endpoints
from better_auth_stripe.schema import StripeOptions, get_schema


STRIPE_ERROR_CODES: Mapping[str, str] = {
    "INVALID_SIGNATURE": "Stripe webhook signature did not match.",
    "PLAN_NOT_FOUND": "The requested plan is not configured.",
    "REFERENCE_REQUIRED": "A referenceId is required for organization subscriptions.",
}


@dataclass(frozen=True, slots=True)
class _StripePlugin:
    id: str
    schema: PluginSchema
    endpoints: tuple[AuthEndpoint, ...]
    error_codes: Mapping[str, str]
    version: str | None = None
    middlewares: None = None
    hooks: None = None
    on_request: None = None
    on_response: None = None
    rate_limit: None = None
    init: None = None


def stripe(options: StripeOptions) -> BetterAuthPlugin:
    """Construct the better-auth Stripe plugin.

    All API calls go through `options.stripe_client` which must implement the
    duck-typed surface in `better_auth_stripe.client.StripeClient`. Tests can
    pass a `StripeClient(transport=mock_stripe.mock_transport())` directly.
    """
    return _StripePlugin(  # type: ignore[return-value]
        id="stripe",
        schema=get_schema(),
        endpoints=build_endpoints(options),
        error_codes=dict(STRIPE_ERROR_CODES),
    )


__all__ = ["stripe", "STRIPE_ERROR_CODES"]
