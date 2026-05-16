"""Seat-sync: keep Stripe subscription quantity == organization member count.

When the better-auth Stripe plugin is configured with ``subscription_for="organization"``
and the active plan declares ``seats=True``, this module's ``register`` hooks the
in-process event bus (``better_auth.events``) and updates the Stripe subscription
quantity whenever the organization plugin emits a member-added or member-removed
event.

Mirrors what the TS reference does via its `organizationSubscriptionHook` —
ported here as a Python event subscriber so it works regardless of which
plugins ship the org events (we only depend on the event name + payload).
"""

from __future__ import annotations

import logging

from better_auth.events import MemberEvent, get_bus
from better_auth.types.adapter import Where
from better_auth.types.context import AuthContext
from better_auth_stripe.schema import StripeOptions

_log = logging.getLogger("better_auth.stripe.seat_sync")


def _seat_plan_ids(options: StripeOptions) -> set[str]:
    return {name for name, plan in options.plans.items() if plan.seats}


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
    """Find active seat-mode subscriptions for an org and update their quantity.

    No-op if there are no matching subscriptions (e.g. the org never bought one).
    """
    seat_plans = _seat_plan_ids(options)
    if not seat_plans:
        return
    rows = await auth.adapter.find_many(
        model="subscription",
        where=(
            Where(field="referenceId", value=organization_id),
            Where(field="status", value="active"),
        ),
    )
    if not rows:
        return
    seats = await _count_org_members(auth, organization_id)
    for row in rows:
        if row.get("plan") not in seat_plans:
            continue
        stripe_sub_id = row.get("stripeSubscriptionId")
        if not stripe_sub_id:
            continue
        try:
            await options.stripe_client.update_subscription(
                stripe_sub_id, quantity=seats
            )
        except Exception:
            _log.exception(
                "seat-sync: update_subscription failed for %s", stripe_sub_id
            )
            continue
        await auth.adapter.update(
            model="subscription",
            where=(Where(field="id", value=row["id"]),),
            update={"seats": seats},
        )


def register_seat_sync(auth: AuthContext, options: StripeOptions) -> None:
    """Subscribe seat-sync handlers to the event bus.

    Only registers when the plugin is in organization mode AND at least one plan
    is seat-based. Otherwise it's a no-op (no listeners installed).
    """
    if options.subscription_for != "organization":
        return
    if not _seat_plan_ids(options):
        return

    bus = get_bus(auth)

    async def _on_member_change(payload: MemberEvent) -> None:
        await _sync_org_seats(auth, options, payload.organization_id)

    bus.on("organization.member.added", _on_member_change)
    bus.on("organization.member.removed", _on_member_change)


__all__ = ["register_seat_sync"]
