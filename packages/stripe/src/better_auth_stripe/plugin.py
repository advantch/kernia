"""Stripe plugin construction.

Mirrors `reference/packages/stripe/src/index.ts`. The plugin assembles its
endpoints (checkout-session, billing-portal, cancel, restore, resume, list,
webhook), contributes the `subscription` table + `user.stripeCustomerId` /
`organization.stripeCustomerId` columns, and declares its error codes.

When `options.subscription_for == "organization"` and any plan declares
`seats=True`, the plugin's `init` hook subscribes to the in-process event bus
and keeps Stripe quantity in lockstep with org membership.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

from better_auth.types.context import AuthContext
from better_auth.types.db_hooks import DatabaseHooks
from better_auth.types.endpoint import AuthEndpoint
from better_auth.types.plugin import BetterAuthPlugin, PluginSchema

from better_auth_stripe.hooks import build_customer_database_hooks
from better_auth_stripe.routes import build_endpoints
from better_auth_stripe.schema import StripeOptions, get_schema
from better_auth_stripe.seat_sync import register_seat_sync

STRIPE_ERROR_CODES: Mapping[str, str] = {
    "UNAUTHORIZED": "Unauthorized access",
    "INVALID_REQUEST_BODY": "Invalid request body",
    "INVALID_SIGNATURE": "Stripe webhook signature did not match.",
    "SUBSCRIPTION_NOT_FOUND": "Subscription not found",
    "SUBSCRIPTION_PLAN_NOT_FOUND": "Subscription plan not found",
    "PLAN_NOT_FOUND": "The requested plan is not configured.",
    "ALREADY_SUBSCRIBED_PLAN": "You're already subscribed to this plan",
    "REFERENCE_ID_NOT_ALLOWED": "Reference id is not allowed",
    "REFERENCE_REQUIRED": "A referenceId is required for organization subscriptions.",
    "CUSTOMER_NOT_FOUND": "Stripe customer not found for this user",
    "UNABLE_TO_CREATE_CUSTOMER": "Unable to create customer",
    "UNABLE_TO_CREATE_BILLING_PORTAL": "Unable to create billing portal session",
    "STRIPE_SIGNATURE_NOT_FOUND": "Stripe signature not found",
    "STRIPE_WEBHOOK_SECRET_NOT_FOUND": "Stripe webhook secret not found",
    "STRIPE_WEBHOOK_ERROR": "Stripe webhook error",
    "FAILED_TO_CONSTRUCT_STRIPE_EVENT": "Failed to construct Stripe event",
    "FAILED_TO_FETCH_PLANS": "Failed to fetch plans",
    "EMAIL_VERIFICATION_REQUIRED": (
        "Email verification is required before you can subscribe to a plan"
    ),
    "SUBSCRIPTION_NOT_ACTIVE": "Subscription is not active",
    "SUBSCRIPTION_NOT_PENDING_CHANGE": (
        "Subscription has no pending cancellation or scheduled plan change"
    ),
    "ORGANIZATION_NOT_FOUND": "Organization not found",
    "ORGANIZATION_SUBSCRIPTION_NOT_ENABLED": (
        "Organization subscription is not enabled"
    ),
    "AUTHORIZE_REFERENCE_REQUIRED": (
        "Organization subscriptions require authorizeReference callback to be "
        "configured"
    ),
    "ORGANIZATION_HAS_ACTIVE_SUBSCRIPTION": (
        "Cannot delete organization with active subscription"
    ),
    "ORGANIZATION_REFERENCE_ID_REQUIRED": (
        "Reference ID is required. Provide referenceId or set "
        "activeOrganizationId in session"
    ),
}


@dataclass(frozen=True, slots=True)
class _StripePlugin:
    id: str
    schema: PluginSchema
    endpoints: tuple[AuthEndpoint, ...]
    error_codes: Mapping[str, str]
    _options: StripeOptions = field(default=None)  # type: ignore[assignment]
    version: str | None = None
    middlewares: None = None
    hooks: None = None
    database_hooks: DatabaseHooks | None = None
    on_request: None = None
    on_response: None = None
    rate_limit: None = None

    async def init(self, ctx: AuthContext) -> None:
        # Subscribe seat-sync to the event bus. No-op unless org+seats mode.
        register_seat_sync(ctx, self._options)


def stripe(options: StripeOptions) -> BetterAuthPlugin:
    """Construct the better-auth Stripe plugin.

    All API calls go through `options.stripe_client` which must implement the
    duck-typed surface in `better_auth_stripe.client.StripeClient`. Tests can
    pass a `StripeClient(transport=mock_stripe.mock_transport())` directly.
    """
    return _StripePlugin(  # type: ignore[return-value]
        id="stripe",
        schema=get_schema(options),
        endpoints=build_endpoints(options),
        error_codes=dict(STRIPE_ERROR_CODES),
        database_hooks=build_customer_database_hooks(options),
        _options=options,
    )


__all__ = ["stripe", "STRIPE_ERROR_CODES"]
