"""Webhook lifecycle handlers — mirrors `reference/packages/stripe/src/hooks.ts`.

Each handler takes the endpoint context, the plugin options, and a decoded
Stripe event dict and reconciles the local `subscription` row, then invokes any
configured lifecycle callbacks (`on_subscription_*`, free-trial hooks).
"""

from __future__ import annotations

import logging
import time
from typing import Any

from better_auth.types.adapter import Where
from better_auth.types.context import EndpointContext

from better_auth_stripe.metadata import subscription_metadata
from better_auth_stripe.schema import StripeOptions
from better_auth_stripe.utils import (
    is_active_or_trialing,
    is_pending_cancel,
    is_stripe_pending_cancel,
    resolve_plan_item,
    resolve_quantity,
)

_log = logging.getLogger("better_auth.stripe.hooks")


async def _maybe_await(value: Any) -> None:
    if hasattr(value, "__await__"):
        await value


async def _call(hook: Any, *args: Any) -> None:
    if hook is None:
        return
    await _maybe_await(hook(*args))


def _sec(ts: Any) -> int | None:
    return int(ts) if ts is not None else None


async def _find_reference_by_customer(
    ctx: EndpointContext, options: StripeOptions, stripe_customer_id: str
) -> dict[str, str] | None:
    """Find org or user owning a Stripe customer id. Mirrors upstream."""
    if options.organization and options.organization.enabled:
        org = await ctx.auth.adapter.find_one(
            model="organization",
            where=(Where(field="stripeCustomerId", value=stripe_customer_id),),
        )
        if org:
            return {"customerType": "organization", "referenceId": org["id"]}
    user = await ctx.auth.adapter.find_one(
        model="user",
        where=(Where(field="stripeCustomerId", value=stripe_customer_id),),
    )
    if user:
        return {"customerType": "user", "referenceId": user["id"]}
    return None


def _trial_fields(stripe_sub: dict[str, Any]) -> dict[str, Any]:
    if stripe_sub.get("trial_start") and stripe_sub.get("trial_end"):
        return {
            "trialStart": _sec(stripe_sub["trial_start"]),
            "trialEnd": _sec(stripe_sub["trial_end"]),
        }
    return {}


def _schedule_id(stripe_sub: dict[str, Any]) -> str | None:
    schedule = stripe_sub.get("schedule")
    if not schedule:
        return None
    if isinstance(schedule, str):
        return schedule
    return schedule.get("id")


async def on_checkout_session_completed(
    ctx: EndpointContext, options: StripeOptions, event: dict[str, Any]
) -> None:
    try:
        client = options.stripe_client
        checkout_session = (event.get("data") or {}).get("object") or {}
        if checkout_session.get("mode") == "setup" or not options.plans:
            return
        sub_id = checkout_session.get("subscription")
        if not sub_id:
            return
        subscription = await client.get_subscription(sub_id)
        items = (subscription.get("items") or {}).get("data") or []
        resolved = resolve_plan_item(options, items)
        if not resolved:
            _log.warning("Subscription %s has no items matching a plan", sub_id)
            return
        item = resolved["item"]
        plan = resolved["plan"]
        if not plan:
            return
        checkout_meta = subscription_metadata.get(checkout_session.get("metadata"))
        reference_id = (
            checkout_session.get("client_reference_id")
            or checkout_meta.get("referenceId")
        )
        subscription_id = checkout_meta.get("subscriptionId")
        seats = resolve_quantity(items, item, plan.seat_price_id)
        if reference_id and subscription_id:
            trial = _trial_fields(subscription)
            update = {
                **trial,
                "plan": plan.name.lower(),
                "status": subscription.get("status"),
                "updatedAt": int(time.time()),
                "periodStart": _sec(item.get("current_period_start")),
                "periodEnd": _sec(item.get("current_period_end")),
                "stripeSubscriptionId": sub_id,
                "cancelAtPeriodEnd": bool(subscription.get("cancel_at_period_end")),
                "cancelAt": _sec(subscription.get("cancel_at")),
                "canceledAt": _sec(subscription.get("canceled_at")),
                "endedAt": _sec(subscription.get("ended_at")),
                "seats": seats,
                "billingInterval": (item.get("price") or {}).get("recurring", {}).get(
                    "interval"
                ),
            }
            await ctx.auth.adapter.update(
                model="subscription",
                where=(Where(field="id", value=subscription_id),),
                update=update,
            )
            db_sub = await ctx.auth.adapter.find_one(
                model="subscription",
                where=(Where(field="id", value=subscription_id),),
            )
            if trial.get("trialStart") and plan.free_trial and plan.free_trial.on_trial_start:
                await _call(plan.free_trial.on_trial_start, db_sub)
            await _call(
                options.on_subscription_complete,
                {
                    "event": event,
                    "subscription": db_sub,
                    "stripeSubscription": subscription,
                    "plan": plan,
                },
                ctx,
            )
    except Exception as e:  # pragma: no cover - mirrors upstream best-effort
        _log.error("Stripe webhook failed: %s", e)


async def on_subscription_created(
    ctx: EndpointContext, options: StripeOptions, event: dict[str, Any]
) -> None:
    try:
        if not options.plans:
            return
        stripe_sub = (event.get("data") or {}).get("object") or {}
        stripe_customer_id = stripe_sub.get("customer")
        if not stripe_customer_id:
            return
        meta = subscription_metadata.get(stripe_sub.get("metadata"))
        subscription_id = meta.get("subscriptionId")
        where = (
            (Where(field="id", value=subscription_id),)
            if subscription_id
            else (Where(field="stripeSubscriptionId", value=stripe_sub["id"]),)
        )
        existing = await ctx.auth.adapter.find_one(model="subscription", where=where)
        if existing:
            return

        reference = await _find_reference_by_customer(
            ctx, options, stripe_customer_id
        )
        if not reference:
            _log.warning("No reference for stripeCustomerId %s", stripe_customer_id)
            return
        reference_id = reference["referenceId"]

        items = (stripe_sub.get("items") or {}).get("data") or []
        resolved = resolve_plan_item(options, items)
        if not resolved:
            return
        item = resolved["item"]
        plan = resolved["plan"]
        if not plan:
            return
        seats = resolve_quantity(items, item, plan.seat_price_id)
        now = int(time.time())
        trial = _trial_fields(stripe_sub)
        data = {
            **trial,
            "referenceId": reference_id,
            "stripeCustomerId": stripe_customer_id,
            "stripeSubscriptionId": stripe_sub["id"],
            "status": stripe_sub.get("status"),
            "plan": plan.name.lower(),
            "periodStart": _sec(item.get("current_period_start")),
            "periodEnd": _sec(item.get("current_period_end")),
            "seats": seats,
            "billingInterval": (item.get("price") or {})
            .get("recurring", {})
            .get("interval"),
            "createdAt": now,
            "updatedAt": now,
        }
        new_sub = await ctx.auth.adapter.create(model="subscription", data=data)
        await _call(
            options.on_subscription_created,
            {
                "event": event,
                "subscription": new_sub,
                "stripeSubscription": stripe_sub,
                "plan": plan,
            },
        )
    except Exception as e:  # pragma: no cover
        _log.error("Stripe webhook failed: %s", e)


async def on_subscription_updated(
    ctx: EndpointContext, options: StripeOptions, event: dict[str, Any]
) -> None:
    try:
        if not options.plans:
            return
        stripe_sub = (event.get("data") or {}).get("object") or {}
        items = (stripe_sub.get("items") or {}).get("data") or []
        resolved = resolve_plan_item(options, items)
        if not resolved:
            return
        item = resolved["item"]
        plan = resolved["plan"]

        meta = subscription_metadata.get(stripe_sub.get("metadata"))
        subscription_id = meta.get("subscriptionId")
        customer_id = stripe_sub.get("customer")
        where = (
            (Where(field="id", value=subscription_id),)
            if subscription_id
            else (Where(field="stripeSubscriptionId", value=stripe_sub["id"]),)
        )
        subscription = await ctx.auth.adapter.find_one(
            model="subscription", where=where
        )
        if not subscription:
            subs = await ctx.auth.adapter.find_many(
                model="subscription",
                where=(Where(field="stripeCustomerId", value=customer_id),),
            )
            subs = list(subs)
            if len(subs) > 1:
                active = next((s for s in subs if is_active_or_trialing(s)), None)
                if not active:
                    return
                subscription = active
            elif subs:
                subscription = subs[0]
            else:
                return

        seats = (
            resolve_quantity(items, item, plan.seat_price_id)
            if plan
            else item.get("quantity")
        )
        trial = _trial_fields(stripe_sub)
        update = {
            **trial,
            **(
                {"plan": plan.name.lower(), "limits": dict(plan.limits or {}) or None}
                if plan
                else {}
            ),
            "updatedAt": int(time.time()),
            "status": stripe_sub.get("status"),
            "periodStart": _sec(item.get("current_period_start")),
            "periodEnd": _sec(item.get("current_period_end")),
            "cancelAtPeriodEnd": bool(stripe_sub.get("cancel_at_period_end")),
            "cancelAt": _sec(stripe_sub.get("cancel_at")),
            "canceledAt": _sec(stripe_sub.get("canceled_at")),
            "endedAt": _sec(stripe_sub.get("ended_at")),
            "seats": seats,
            "stripeSubscriptionId": stripe_sub["id"],
            "billingInterval": (item.get("price") or {})
            .get("recurring", {})
            .get("interval"),
            "stripeScheduleId": _schedule_id(stripe_sub),
        }
        # `limits` is not a persisted column; strip None entry to avoid noise.
        if update.get("limits") is None:
            update.pop("limits", None)
        await ctx.auth.adapter.update(
            model="subscription",
            where=(Where(field="id", value=subscription["id"]),),
            update=update,
        )
        updated = await ctx.auth.adapter.find_one(
            model="subscription",
            where=(Where(field="id", value=subscription["id"]),),
        )

        is_new_cancellation = (
            stripe_sub.get("status") == "active"
            and is_stripe_pending_cancel(stripe_sub)
            and not is_pending_cancel(subscription)
        )
        if is_new_cancellation:
            await _call(
                options.on_subscription_cancel,
                {
                    "event": event,
                    "subscription": updated,
                    "stripeSubscription": stripe_sub,
                    "cancellationDetails": stripe_sub.get("cancellation_details"),
                },
            )
        await _call(
            options.on_subscription_update,
            {
                "event": event,
                "subscription": updated,
                "stripeSubscription": stripe_sub,
            },
        )
        if plan and plan.free_trial:
            if (
                stripe_sub.get("status") == "active"
                and subscription.get("status") == "trialing"
                and plan.free_trial.on_trial_end
            ):
                await _call(
                    plan.free_trial.on_trial_end, {"subscription": updated}, ctx
                )
            if (
                stripe_sub.get("status") == "incomplete_expired"
                and subscription.get("status") == "trialing"
                and plan.free_trial.on_trial_expired
            ):
                await _call(plan.free_trial.on_trial_expired, updated, ctx)
    except Exception as e:  # pragma: no cover
        _log.error("Stripe webhook failed: %s", e)


async def on_subscription_deleted(
    ctx: EndpointContext, options: StripeOptions, event: dict[str, Any]
) -> None:
    if not options.plans:
        return
    try:
        stripe_sub = (event.get("data") or {}).get("object") or {}
        subscription_id = stripe_sub.get("id")
        subscription = await ctx.auth.adapter.find_one(
            model="subscription",
            where=(Where(field="stripeSubscriptionId", value=subscription_id),),
        )
        if not subscription:
            _log.warning("Subscription not found for %s", subscription_id)
            return
        trial = _trial_fields(stripe_sub)
        update = {
            **trial,
            "status": "canceled",
            "updatedAt": int(time.time()),
            "cancelAtPeriodEnd": bool(stripe_sub.get("cancel_at_period_end")),
            "cancelAt": _sec(stripe_sub.get("cancel_at")),
            "canceledAt": _sec(stripe_sub.get("canceled_at")),
            "endedAt": _sec(stripe_sub.get("ended_at")),
            "stripeScheduleId": None,
        }
        await ctx.auth.adapter.update(
            model="subscription",
            where=(Where(field="id", value=subscription["id"]),),
            update=update,
        )
        updated = await ctx.auth.adapter.find_one(
            model="subscription",
            where=(Where(field="id", value=subscription["id"]),),
        )
        await _call(
            options.on_subscription_deleted,
            {
                "event": event,
                "stripeSubscription": stripe_sub,
                "subscription": updated,
            },
        )
    except Exception as e:  # pragma: no cover
        _log.error("Stripe webhook failed: %s", e)


__all__ = [
    "on_checkout_session_completed",
    "on_subscription_created",
    "on_subscription_deleted",
    "on_subscription_updated",
]
