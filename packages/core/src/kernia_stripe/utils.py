"""Shared helpers — mirrors `reference/packages/stripe/src/utils.ts`."""

from __future__ import annotations

from typing import Any

from kernia_stripe.schema import StripeOptions, StripePlan


def get_plans(options: StripeOptions) -> list[StripePlan]:
    """Return configured plans as a list (parity with upstream `getPlans`)."""
    return list(options.plans.values())


def get_plan_by_name(options: StripeOptions, name: str) -> StripePlan | None:
    """Case-insensitive plan lookup. Mirrors `getPlanByName`."""
    lowered = name.lower()
    for plan in options.plans.values():
        if plan.name.lower() == lowered:
            return plan
    return None


def is_active_or_trialing(sub: dict[str, Any]) -> bool:
    """True when a (DB or Stripe) subscription is active or trialing."""
    return sub.get("status") in ("active", "trialing")


def is_pending_cancel(sub: dict[str, Any]) -> bool:
    """True when a DB subscription row is scheduled to be canceled."""
    return bool(sub.get("cancelAtPeriodEnd") or sub.get("cancelAt"))


def is_stripe_pending_cancel(stripe_sub: dict[str, Any]) -> bool:
    """True when a Stripe subscription object is scheduled to be canceled."""
    return bool(stripe_sub.get("cancel_at_period_end") or stripe_sub.get("cancel_at"))


def escape_stripe_search_value(value: str) -> str:
    """Escape a value for use in Stripe search queries."""
    return value.replace('"', '\\"')


def resolve_quantity(
    items: list[dict[str, Any]],
    plan_item: dict[str, Any],
    seat_price_id: str | None = None,
) -> int:
    """Resolve a subscription's quantity, preferring the seat item."""
    if seat_price_id:
        for item in items:
            if (item.get("price") or {}).get("id") == seat_price_id:
                return item.get("quantity") or 1
    return plan_item.get("quantity") or 1


def resolve_plan_item(
    options: StripeOptions,
    items: list[dict[str, Any]],
) -> dict[str, Any] | None:
    """Resolve the plan-matching subscription item + its plan config.

    Returns ``{"item": <stripe item>, "plan": <StripePlan | None>}`` or ``None``.
    Mirrors `resolvePlanItem`: scans items for one whose price matches a
    configured plan; for single-item subscriptions returns the item even without
    a plan match.
    """
    if not items:
        return None
    first = items[0]
    plans = get_plans(options)
    for item in items:
        price = item.get("price") or {}
        price_id = price.get("id")
        lookup_key = price.get("lookup_key")
        for plan in plans:
            if (
                plan.price_id == price_id
                or plan.annual_price_id == price_id
                or plan.annual_discount_price_id == price_id
                or (
                    lookup_key
                    and (
                        plan.lookup_key == lookup_key
                        or plan.annual_discount_lookup_key == lookup_key
                    )
                )
            ):
                return {"item": item, "plan": plan}
    if len(items) == 1:
        return {"item": first, "plan": None}
    return None


__all__ = [
    "escape_stripe_search_value",
    "get_plan_by_name",
    "get_plans",
    "is_active_or_trialing",
    "is_pending_cancel",
    "is_stripe_pending_cancel",
    "resolve_plan_item",
    "resolve_quantity",
]
