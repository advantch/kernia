"""Stripe plugin schema + options.

Mirrors `reference/packages/stripe/src/schema.ts` (subscription model + user
extension) and `types.ts` (plan definition, plugin options).
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Literal

from kernia.types.adapter import FieldDef, ModelDef
from kernia.types.plugin import PluginSchema


SubscriptionFor = Literal["user", "organization"]


@dataclass(frozen=True, slots=True)
class StripePlan:
    """Declarative plan definition. Mirrors `StripePlan` in the TS port.

    `seats=True` flips the plan into seat-based mode; when the plugin is
    configured for organization billing the quantity tracks org membership.
    """

    name: str
    price_id: str
    seats: bool = False
    seat_price_id: str | None = None
    free_trial_days: int | None = None
    annual_price_id: str | None = None
    lookup_key: str | None = None


SubscriptionRow = dict[str, Any]
CustomerHook = Callable[[Mapping[str, Any]], Awaitable[None]]


@dataclass
class StripeOptions:
    """Configuration the user passes into `stripe(options=...)`.

    `stripe_client` is duck-typed; we only call the methods needed (`customers`,
    `checkout.sessions`, `subscriptions`, `billingPortal.sessions`, `webhooks`).
    Tests can inject `MockStripe` configured with an httpx mock transport, plus
    a stubbed `webhooks` namespace whose `construct_event` short-circuits to
    `MockStripe.emit_webhook`'s verifier.
    """

    stripe_client: Any
    webhook_secret: str
    plans: Mapping[str, StripePlan] = field(default_factory=dict)
    subscription_for: SubscriptionFor = "user"
    create_customer_on_sign_up: bool = True
    on_event: CustomerHook | None = None


# ----- schema contribution --------------------------------------------------


SUBSCRIPTION_MODEL = ModelDef(
    name="subscription",
    fields=(
        FieldDef(name="id", type="string", required=True, unique=True),
        FieldDef(name="plan", type="string", required=True),
        FieldDef(name="referenceId", type="string", required=True),
        FieldDef(name="stripeCustomerId", type="string", required=False),
        FieldDef(name="stripeSubscriptionId", type="string", required=False),
        FieldDef(name="status", type="string", required=True),
        FieldDef(name="periodStart", type="number", required=False),
        FieldDef(name="periodEnd", type="number", required=False),
        FieldDef(name="cancelAtPeriodEnd", type="boolean", required=False),
        FieldDef(name="seats", type="number", required=False),
        FieldDef(name="trialStart", type="number", required=False),
        FieldDef(name="trialEnd", type="number", required=False),
        FieldDef(name="createdAt", type="number", required=True),
        FieldDef(name="updatedAt", type="number", required=True),
    ),
)

BILLING_PRODUCT_MODEL = ModelDef(
    name="billingProduct",
    fields=(
        FieldDef("id", "string", unique=True),
        FieldDef("stripeProductId", "string", required=True),
        FieldDef("name", "string", required=True),
        FieldDef("active", "boolean", required=False),
        FieldDef("metadata", "json", required=False),
        FieldDef("createdAt", "number", required=True),
        FieldDef("updatedAt", "number", required=True),
    ),
)

BILLING_PRICE_MODEL = ModelDef(
    name="billingPrice",
    fields=(
        FieldDef("id", "string", unique=True),
        FieldDef("stripePriceId", "string", required=True),
        FieldDef("stripeProductId", "string", required=True),
        FieldDef("currency", "string", required=True),
        FieldDef("unitAmount", "number", required=False),
        FieldDef("interval", "string", required=False),
        FieldDef("lookupKey", "string", required=False),
        FieldDef("active", "boolean", required=False),
        FieldDef("metadata", "json", required=False),
        FieldDef("createdAt", "number", required=True),
        FieldDef("updatedAt", "number", required=True),
    ),
)

BILLING_FEATURE_MODEL = ModelDef(
    name="billingFeature",
    fields=(
        FieldDef("id", "string", unique=True),
        FieldDef("key", "string", required=True),
        FieldDef("name", "string", required=True),
        FieldDef("type", "string", required=True),  # boolean | metered | quantity
        FieldDef("metadata", "json", required=False),
        FieldDef("createdAt", "number", required=True),
        FieldDef("updatedAt", "number", required=True),
    ),
)

BILLING_PLAN_MODEL = ModelDef(
    name="billingPlan",
    fields=(
        FieldDef("id", "string", unique=True),
        FieldDef("key", "string", required=True),
        FieldDef("name", "string", required=True),
        FieldDef("stripeProductId", "string", required=False),
        FieldDef("stripePriceId", "string", required=False),
        FieldDef("active", "boolean", required=False),
        FieldDef("createdAt", "number", required=True),
        FieldDef("updatedAt", "number", required=True),
    ),
)

BILLING_PLAN_FEATURE_MODEL = ModelDef(
    name="billingPlanFeature",
    fields=(
        FieldDef("id", "string", unique=True),
        FieldDef("planKey", "string", required=True),
        FieldDef("featureKey", "string", required=True),
        FieldDef("included", "number", required=False),
        FieldDef("unlimited", "boolean", required=False),
        FieldDef("resetPeriod", "string", required=False),
        FieldDef("overageAllowed", "boolean", required=False),
        FieldDef("createdAt", "number", required=True),
        FieldDef("updatedAt", "number", required=True),
    ),
)

BILLING_ENTITLEMENT_MODEL = ModelDef(
    name="billingEntitlement",
    fields=(
        FieldDef("id", "string", unique=True),
        FieldDef("referenceId", "string", required=True),
        FieldDef("featureKey", "string", required=True),
        FieldDef("included", "number", required=False),
        FieldDef("used", "number", required=False),
        FieldDef("unlimited", "boolean", required=False),
        FieldDef("resetPeriod", "string", required=False),
        FieldDef("resetsAt", "number", required=False),
        FieldDef("overageAllowed", "boolean", required=False),
        FieldDef("createdAt", "number", required=True),
        FieldDef("updatedAt", "number", required=True),
    ),
)

BILLING_USAGE_EVENT_MODEL = ModelDef(
    name="billingUsageEvent",
    fields=(
        FieldDef("id", "string", unique=True),
        FieldDef("referenceId", "string", required=True),
        FieldDef("featureKey", "string", required=True),
        FieldDef("quantity", "number", required=True),
        FieldDef("properties", "json", required=False),
        FieldDef("createdAt", "number", required=True),
    ),
)

BILLING_CUSTOMER_MODEL = ModelDef(
    name="billingCustomer",
    fields=(
        FieldDef("id", "string", unique=True),
        FieldDef("referenceId", "string", required=True),
        FieldDef("stripeCustomerId", "string", required=False),
        FieldDef("email", "string", required=False),
        FieldDef("name", "string", required=False),
        FieldDef("createdAt", "number", required=True),
        FieldDef("updatedAt", "number", required=True),
    ),
)

BILLING_SYNC_STATE_MODEL = ModelDef(
    name="billingSyncState",
    fields=(
        FieldDef("id", "string", unique=True),
        FieldDef("source", "string", required=True),
        FieldDef("status", "string", required=True),
        FieldDef("message", "string", required=False),
        FieldDef("syncedAt", "number", required=True),
    ),
)


USER_EXTENSIONS: Mapping[str, tuple[FieldDef, ...]] = {
    "user": (FieldDef(name="stripeCustomerId", type="string", required=False),),
}


def get_schema() -> PluginSchema:
    """Return the `PluginSchema` contributed by the stripe plugin."""
    return PluginSchema(
        tables=(
            SUBSCRIPTION_MODEL,
            BILLING_PRODUCT_MODEL,
            BILLING_PRICE_MODEL,
            BILLING_FEATURE_MODEL,
            BILLING_PLAN_MODEL,
            BILLING_PLAN_FEATURE_MODEL,
            BILLING_ENTITLEMENT_MODEL,
            BILLING_USAGE_EVENT_MODEL,
            BILLING_CUSTOMER_MODEL,
            BILLING_SYNC_STATE_MODEL,
        ),
        extend=USER_EXTENSIONS,
    )


__all__ = [
    "SUBSCRIPTION_MODEL",
    "USER_EXTENSIONS",
    "BILLING_CUSTOMER_MODEL",
    "BILLING_ENTITLEMENT_MODEL",
    "BILLING_FEATURE_MODEL",
    "BILLING_PLAN_FEATURE_MODEL",
    "BILLING_PLAN_MODEL",
    "BILLING_PRICE_MODEL",
    "BILLING_PRODUCT_MODEL",
    "BILLING_SYNC_STATE_MODEL",
    "BILLING_USAGE_EVENT_MODEL",
    "StripeOptions",
    "StripePlan",
    "SubscriptionFor",
    "get_schema",
]
