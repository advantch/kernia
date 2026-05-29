"""Stripe plugin schema + options.

Mirrors `reference/packages/stripe/src/schema.ts` (subscription model + user
extension) and `types.ts` (plan definition, plugin options).
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Literal

from better_auth.types.adapter import FieldDef, ModelDef
from better_auth.types.plugin import PluginSchema


SubscriptionFor = Literal["user", "organization"]


@dataclass(frozen=True, slots=True)
class StripePlan:
    """Declarative plan definition. Mirrors `StripePlan` in the TS port.

    `seats=True` flips the plan into seat-based mode; when the plugin is
    configured for organization billing the quantity tracks org membership.

    Metered / usage-based billing
    -----------------------------
    Set ``metered=True`` (or point ``price_id`` / ``lookup_key`` at a Stripe
    price whose ``recurring.usage_type == "metered"``) to bill by reported
    usage. For metered prices Stripe rejects a ``quantity`` on the line item,
    so the plugin omits it — see :func:`routes.is_metered_price`.

    ``proration_behavior`` controls how mid-cycle plan changes are billed on
    ``/subscription/upgrade`` (``create_prorations`` (default) / ``always_invoice``
    / ``none``). ``line_items`` are extra checkout line items (add-ons, metered
    usage prices) appended to the base price. ``group`` lets a reference id hold
    multiple concurrent subscriptions (one per group). ``limits`` is opaque
    plan metadata surfaced to the app.
    """

    name: str
    price_id: str
    seats: bool = False
    seat_price_id: str | None = None
    free_trial_days: int | None = None
    annual_price_id: str | None = None
    annual_discount_price_id: str | None = None
    lookup_key: str | None = None
    annual_discount_lookup_key: str | None = None
    metered: bool = False
    proration_behavior: str = "create_prorations"
    group: str | None = None
    limits: Mapping[str, Any] | None = None
    line_items: tuple[Mapping[str, Any], ...] = ()


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
        # Metered / upgrade / schedule support (parity with upstream schema.ts).
        FieldDef(name="priceId", type="string", required=False),
        FieldDef(name="groupId", type="string", required=False),
        FieldDef(name="billingInterval", type="string", required=False),
        FieldDef(name="stripeScheduleId", type="string", required=False),
        FieldDef(name="createdAt", type="number", required=True),
        FieldDef(name="updatedAt", type="number", required=True),
    ),
)


USER_EXTENSIONS: Mapping[str, tuple[FieldDef, ...]] = {
    "user": (FieldDef(name="stripeCustomerId", type="string", required=False),),
}


def get_schema() -> PluginSchema:
    """Return the `PluginSchema` contributed by the stripe plugin."""
    return PluginSchema(tables=(SUBSCRIPTION_MODEL,), extend=USER_EXTENSIONS)


__all__ = [
    "SUBSCRIPTION_MODEL",
    "USER_EXTENSIONS",
    "StripeOptions",
    "StripePlan",
    "SubscriptionFor",
    "get_schema",
]
