"""Stripe plugin schema + options.

Mirrors `reference/packages/stripe/src/schema.ts` (subscription model + user
extension) and `types.ts` (plan definition, plugin options, lifecycle hooks).
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Literal

from kernia.types.adapter import FieldDef, ModelDef
from kernia.types.plugin import PluginSchema

SubscriptionFor = Literal["user", "organization"]


@dataclass(frozen=True, slots=True)
class FreeTrial:
    """Free-trial config for a plan. Mirrors `StripePlan.freeTrial`.

    The callbacks receive the persisted local subscription row (a dict). They are
    optional and may be sync or async.
    """

    days: int
    on_trial_start: Callable[[dict[str, Any]], Awaitable[None] | None] | None = None
    on_trial_end: Callable[[dict[str, Any], Any], Awaitable[None] | None] | None = None
    on_trial_expired: Callable[[dict[str, Any], Any], Awaitable[None] | None] | None = None


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
    plan metadata surfaced to the app. ``free_trial`` configures a per-plan trial
    with optional lifecycle callbacks.
    """

    name: str
    price_id: str | None = None
    seats: bool = False
    seat_price_id: str | None = None
    free_trial_days: int | None = None
    free_trial: FreeTrial | None = None
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
# Generic async-or-sync callback type used by lifecycle hooks. The first arg is
# a data dict; an optional second arg is the endpoint context.
Hook = Callable[..., Awaitable[None] | None]


@dataclass
class OrganizationStripeOptions:
    """Mirrors `StripeOptions.organization`."""

    enabled: bool = True
    get_customer_create_params: Callable[..., Any] | None = None
    on_customer_create: Hook | None = None


@dataclass
class StripeOptions:
    """Configuration the user passes into `stripe(options=...)`.

    `stripe_client` is duck-typed; we only call the methods needed (`customers`,
    `checkout.sessions`, `subscriptions`, `billingPortal.sessions`, `webhooks`).
    Tests can inject a `StripeClient` wired to `MockStripe.mock_transport()`.

    Lifecycle hooks mirror upstream's `SubscriptionOptions` and top-level
    `StripeOptions` callbacks. All hooks may be sync or async.
    """

    stripe_client: Any
    webhook_secret: str
    plans: Mapping[str, StripePlan] = field(default_factory=dict)
    subscription_for: SubscriptionFor = "user"
    create_customer_on_sign_up: bool = True
    require_email_verification: bool = False

    # top-level callbacks
    on_event: Hook | None = None
    on_customer_create: Hook | None = None
    get_customer_create_params: Callable[..., Any] | None = None

    # subscription lifecycle callbacks
    on_subscription_complete: Hook | None = None
    on_subscription_created: Hook | None = None
    on_subscription_update: Hook | None = None
    on_subscription_cancel: Hook | None = None
    on_subscription_deleted: Hook | None = None
    authorize_reference: Callable[..., Any] | None = None
    get_checkout_session_params: Callable[..., Any] | None = None

    # organization integration
    organization: OrganizationStripeOptions | None = None


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
        FieldDef(name="cancelAt", type="number", required=False),
        FieldDef(name="canceledAt", type="number", required=False),
        FieldDef(name="endedAt", type="number", required=False),
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


_USER_EXTENSION = (FieldDef(name="stripeCustomerId", type="string", required=False),)
_ORGANIZATION_EXTENSION = (FieldDef(name="stripeCustomerId", type="string", required=False),)

# Static view of every column the plugin may contribute, used by tests/introspection.
USER_EXTENSIONS: Mapping[str, tuple[FieldDef, ...]] = {
    "user": _USER_EXTENSION,
    "organization": _ORGANIZATION_EXTENSION,
}


def get_schema(options: StripeOptions | None = None) -> PluginSchema:
    """Return the `PluginSchema` contributed by the stripe plugin.

    Mirrors `getSchema` in schema.ts: the `user` table always gains
    `stripeCustomerId`, but the `organization` table is only extended when
    organization billing is enabled (otherwise the column would target a model
    that may not exist).
    """
    extend: dict[str, tuple[FieldDef, ...]] = {"user": _USER_EXTENSION}
    if options is not None and options.organization and options.organization.enabled:
        extend["organization"] = _ORGANIZATION_EXTENSION
    return PluginSchema(tables=(SUBSCRIPTION_MODEL,), extend=extend)


__all__ = [
    "SUBSCRIPTION_MODEL",
    "USER_EXTENSIONS",
    "FreeTrial",
    "OrganizationStripeOptions",
    "StripeOptions",
    "StripePlan",
    "SubscriptionFor",
    "get_schema",
]
