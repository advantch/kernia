"""Seat-sync: keep the seat line-item quantity == organization member count.

When the Kernia Stripe plugin is configured with ``subscription_for="organization"``
and the active plan declares ``seats=True``, this module's ``register`` hooks the
in-process event bus (``kernia.events``) and updates the Stripe subscription
quantity whenever the organization plugin emits a member-added or member-removed
event.

Faithful port of ``syncSeatsAfterMemberChange`` in
``reference/packages/stripe/src/index.ts`` (lines ~176-254): gate on the
organization integration being enabled, count members, find the org's
subscription, require it to be active/trialing on a seat plan, retrieve the
Stripe subscription, locate the seat item by ``price.id == seat_price_id``,
skip when the quantity already matches, then update that item's quantity with
the plan's ``proration_behavior`` (default ``create_prorations``).
"""

from __future__ import annotations

import logging

from kernia.events import MemberEvent, get_bus
from kernia.types.adapter import Where
from kernia.types.context import AuthContext
from kernia_stripe.schema import StripeOptions

_log = logging.getLogger("kernia.stripe.seat_sync")


def _seat_plans(options: StripeOptions) -> dict[str, StripePlan]:
    """Plans that declare a ``seat_price_id``, keyed by lowercased plan name.

    Mirrors upstream's ``plans.filter(p => p.seatPriceId)`` + the
    ``seatPlanNames`` set (compared case-insensitively against ``dbSub.plan``).
    """
    return {
        plan.name.lower(): plan
        for plan in options.plans.values()
        if plan.seat_price_id
    }


async def _count_org_members(auth: AuthContext, organization_id: str) -> int:
    return await auth.adapter.count(
        model="member",
        where=(Where(field="organizationId", value=organization_id),),
    )


async def _sync_org_seats(
    auth: AuthContext,
    options: StripeOptions,
    organization_id: str,
) -> None:
    """Update the seat line-item quantity for an org's subscription.

    No-op when there are no seat plans, no active subscription on a seat plan,
    or the quantity already matches the member count.
    """
    seat_plans = _seat_plans(options)
    if not seat_plans:
        return

    try:
        member_count = await _count_org_members(auth, organization_id)

        db_sub = await auth.adapter.find_one(
            model="subscription",
            where=(Where(field="referenceId", value=organization_id),),
        )
        if (
            not db_sub
            or not db_sub.get("stripeSubscriptionId")
            or not is_active_or_trialing(db_sub)
            or db_sub.get("plan") not in seat_plans
        ):
            return

        plan = seat_plans[db_sub["plan"]]
        seat_price_id = plan.seat_price_id

        stripe_sub = await options.stripe_client.get_subscription(
            db_sub["stripeSubscriptionId"]
        )
        if not is_active_or_trialing(stripe_sub):
            return

        items_data = (stripe_sub.get("items") or {}).get("data") or []
        seat_item = next(
            (i for i in items_data if (i.get("price") or {}).get("id") == seat_price_id),
            None,
        )

        # Skip if no change needed.
        if seat_item is not None and seat_item.get("quantity") == member_count:
            return

        if seat_item is not None:
            items = [{"id": seat_item["id"], "quantity": member_count}]
        else:
            items = [{"price": seat_price_id, "quantity": member_count}]

        await options.stripe_client.update_subscription(
            stripe_sub["id"],
            items=items,
            proration_behavior=plan.proration_behavior or "create_prorations",
        )
        await auth.adapter.update(
            model="subscription",
            where=(Where(field="id", value=db_sub["id"]),),
            update={"seats": member_count},
        )
    except Exception:  # pragma: no cover - mirrors upstream's catch-and-log
        _log.exception("Failed to sync seats to Stripe")


def register_seat_sync(auth: AuthContext, options: StripeOptions) -> None:
    """Subscribe seat-sync handlers to the event bus.

    Only registers when the organization integration is enabled AND at least
    one plan declares a ``seat_price_id``. Otherwise it's a no-op (no listeners
    installed), matching upstream's ``options.subscription?.enabled`` +
    seat-plan gate.
    """
    if not (options.organization and options.organization.enabled):
        return
    if not _seat_plans(options):
        return

    bus = get_bus(auth)

    async def _on_member_change(payload: MemberEvent) -> None:
        await _sync_org_seats(auth, options, payload.organization_id)

    bus.on("organization.member.added", _on_member_change)
    bus.on("organization.member.removed", _on_member_change)


__all__ = ["register_seat_sync"]
