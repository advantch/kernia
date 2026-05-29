"""HTTP endpoints for the Stripe plugin.

Mirrors `reference/packages/stripe/src/routes.ts` at a Python-port granularity:
just enough surface to support a complete checkout → webhook → subscription
lifecycle through the test driver.
"""

from __future__ import annotations

import json
import time
from typing import Any

from better_auth.api.endpoint import create_auth_endpoint
from better_auth.error import APIError
from better_auth.types.adapter import Where
from better_auth.types.context import EndpointContext
from better_auth.types.endpoint import AuthEndpoint, EndpointOptions
from pydantic import BaseModel

from better_auth_stripe.schema import StripeOptions, StripePlan
from better_auth_stripe.webhook import verify_signature

# ----- request bodies -------------------------------------------------------


class CheckoutSessionBody(BaseModel):
    plan: str
    successUrl: str
    cancelUrl: str
    referenceId: str | None = None
    seats: int | None = None


class BillingPortalBody(BaseModel):
    returnUrl: str
    referenceId: str | None = None


class CancelSubscriptionBody(BaseModel):
    subscriptionId: str
    cancelAtPeriodEnd: bool = True


class ResumeSubscriptionBody(BaseModel):
    subscriptionId: str


class UpgradeSubscriptionBody(BaseModel):
    plan: str
    annual: bool | None = None
    referenceId: str | None = None
    subscriptionId: str
    seats: int | None = None
    successUrl: str | None = None
    cancelUrl: str | None = None
    returnUrl: str | None = None


# ----- helpers --------------------------------------------------------------


def _plan(opts: StripeOptions, name: str) -> StripePlan:
    plan = opts.plans.get(name)
    if plan is None:
        raise APIError(400, "PLAN_NOT_FOUND", message=f"Unknown plan: {name}")
    return plan


def is_metered_price(price: dict[str, Any] | None) -> bool:
    """Return True when a Stripe price uses metered (usage-based) billing.

    Mirrors `isMeteredPrice` in ``reference/packages/stripe/src/routes.ts``:
    ``price?.recurring?.usage_type === "metered"``.
    """
    if not price:
        return False
    recurring = price.get("recurring") or {}
    return recurring.get("usage_type") == "metered"


async def _resolve_price(
    opts: StripeOptions,
    *,
    price_id: str | None,
    lookup_key: str | None,
) -> dict[str, Any] | None:
    """Resolve a Stripe price object by lookup key (preferred) or id.

    Mirrors `resolveStripePrice`: a lookup-key list call wins, otherwise a
    retrieve-by-id. On any error we return ``None`` so callers fall back to
    licensed behavior (i.e. include ``quantity``).
    """
    client = opts.stripe_client
    try:
        if lookup_key:
            listed = await client.list_prices(lookup_keys=[lookup_key], active=True, limit=1)
            data = (listed or {}).get("data") or []
            if data:
                return data[0]
        if price_id:
            return await client.get_price(price_id)
    except Exception:
        return None
    return None


def _plan_price_id(plan: StripePlan, *, annual: bool) -> str:
    """Pick the active price id for a plan honoring the annual toggle."""
    if annual:
        return plan.annual_discount_price_id or plan.annual_price_id or plan.price_id
    return plan.price_id


def _plan_lookup_key(plan: StripePlan, *, annual: bool) -> str | None:
    if annual:
        return plan.annual_discount_lookup_key or plan.lookup_key
    return plan.lookup_key


async def _build_line_items(
    opts: StripeOptions,
    plan: StripePlan,
    *,
    annual: bool,
    seats: int | None,
) -> list[dict[str, Any]]:
    """Build Stripe checkout/subscription line items for a plan.

    A metered base price MUST omit ``quantity`` (Stripe rejects a quantity on
    metered line items). Licensed prices carry the seat quantity. Any extra
    ``plan.line_items`` (add-ons / usage prices) are appended verbatim.
    """
    price_id = _plan_price_id(plan, annual=annual)
    lookup_key = _plan_lookup_key(plan, annual=annual)
    resolved = await _resolve_price(opts, price_id=price_id, lookup_key=lookup_key)
    effective_price_id = (resolved or {}).get("id") or price_id

    base: dict[str, Any] = {"price": effective_price_id}
    if plan.metered or is_metered_price(resolved):
        # Metered: no quantity.
        pass
    else:
        base["quantity"] = seats or 1
    items: list[dict[str, Any]] = [base]
    items.extend(dict(extra) for extra in plan.line_items)
    return items


def _reference_id(ctx: EndpointContext, opts: StripeOptions, body_ref: str | None) -> str:
    if opts.subscription_for == "organization":
        # Per-spec: the org id is supplied explicitly via referenceId in the
        # body. We don't have an organization plugin wired here so the caller
        # provides it directly.
        if not body_ref:
            raise APIError(400, "REFERENCE_REQUIRED", message="referenceId required for org subscriptions")
        return body_ref
    assert ctx.session is not None  # requires_session guarantees this
    return body_ref or ctx.session.user_id


async def _ensure_customer(ctx: EndpointContext, opts: StripeOptions) -> str:
    """Get-or-create a Stripe customer id for the active session's user."""
    assert ctx.session is not None
    user = await ctx.auth.adapter.find_one(
        model="user",
        where=(Where(field="id", value=ctx.session.user_id),),
    )
    if user is None:
        raise APIError(404, "USER_NOT_FOUND")
    customer_id = user.get("stripeCustomerId")
    if customer_id:
        return customer_id
    customer = await opts.stripe_client.create_customer(
        email=user.get("email"),
        name=user.get("name"),
        metadata={"userId": ctx.session.user_id},
    )
    customer_id = customer["id"]
    await ctx.auth.adapter.update(
        model="user",
        where=(Where(field="id", value=ctx.session.user_id),),
        update={"stripeCustomerId": customer_id},
    )
    return customer_id


# ----- handlers -------------------------------------------------------------


def _build_checkout_endpoint(opts: StripeOptions) -> AuthEndpoint:
    async def handler(ctx: EndpointContext) -> dict[str, Any]:
        body: CheckoutSessionBody = ctx.body
        plan = _plan(opts, body.plan)
        reference_id = _reference_id(ctx, opts, body.referenceId)
        customer_id = await _ensure_customer(ctx, opts)

        line_items = await _build_line_items(
            opts, plan, annual=False, seats=body.seats
        )
        params: dict[str, Any] = {
            "mode": "subscription",
            "customer": customer_id,
            "success_url": body.successUrl,
            "cancel_url": body.cancelUrl,
            "line_items": line_items,
            "client_reference_id": reference_id,
            "metadata": {"referenceId": reference_id, "plan": plan.name},
        }
        if plan.free_trial_days:
            params["subscription_data"] = {"trial_period_days": plan.free_trial_days}
        session = await opts.stripe_client.create_checkout_session(**params)
        return {"url": session["url"], "id": session["id"]}

    return create_auth_endpoint(
        "/stripe/checkout-session",
        EndpointOptions(method="POST", body=CheckoutSessionBody, requires_session=True),
        handler,
    )


def _build_billing_portal_endpoint(opts: StripeOptions) -> AuthEndpoint:
    async def handler(ctx: EndpointContext) -> dict[str, Any]:
        body: BillingPortalBody = ctx.body
        customer_id = await _ensure_customer(ctx, opts)
        portal = await opts.stripe_client.create_billing_portal_session(
            customer=customer_id, return_url=body.returnUrl,
        )
        return {"url": portal["url"]}

    return create_auth_endpoint(
        "/stripe/billing-portal",
        EndpointOptions(method="POST", body=BillingPortalBody, requires_session=True),
        handler,
    )


def _build_cancel_endpoint(opts: StripeOptions) -> AuthEndpoint:
    async def handler(ctx: EndpointContext) -> dict[str, Any]:
        body: CancelSubscriptionBody = ctx.body
        sub = await opts.stripe_client.cancel_subscription(
            body.subscriptionId, at_period_end=body.cancelAtPeriodEnd
        )
        # Mirror the new state into our row.
        await ctx.auth.adapter.update(
            model="subscription",
            where=(Where(field="stripeSubscriptionId", value=body.subscriptionId),),
            update={
                "cancelAtPeriodEnd": bool(body.cancelAtPeriodEnd),
                "status": sub.get("status", "canceled"),
                "updatedAt": int(time.time()),
            },
        )
        return {"subscription": sub}

    return create_auth_endpoint(
        "/stripe/cancel-subscription",
        EndpointOptions(method="POST", body=CancelSubscriptionBody, requires_session=True),
        handler,
    )


def _build_resume_endpoint(opts: StripeOptions) -> AuthEndpoint:
    async def handler(ctx: EndpointContext) -> dict[str, Any]:
        body: ResumeSubscriptionBody = ctx.body
        sub = await opts.stripe_client.update_subscription(
            body.subscriptionId, cancel_at_period_end="false"
        )
        await ctx.auth.adapter.update(
            model="subscription",
            where=(Where(field="stripeSubscriptionId", value=body.subscriptionId),),
            update={
                "cancelAtPeriodEnd": False,
                "status": sub.get("status", "active"),
                "updatedAt": int(time.time()),
            },
        )
        return {"subscription": sub}

    return create_auth_endpoint(
        "/stripe/resume-subscription",
        EndpointOptions(method="POST", body=ResumeSubscriptionBody, requires_session=True),
        handler,
    )


def _build_upgrade_endpoint(opts: StripeOptions) -> AuthEndpoint:
    async def handler(ctx: EndpointContext) -> dict[str, Any]:
        body: UpgradeSubscriptionBody = ctx.body
        plan = _plan(opts, body.plan)
        annual = bool(body.annual)
        reference_id = _reference_id(ctx, opts, body.referenceId)
        # Ensure a Stripe customer exists for the active session (parity with
        # upstream upgrade, which resolves the customer before mutating).
        await _ensure_customer(ctx, opts)

        line_items = await _build_line_items(
            opts, plan, annual=annual, seats=body.seats
        )
        price_id = line_items[0].get("price")
        billing_interval = "year" if annual else "month"

        existing_sub = await opts.stripe_client.get_subscription(body.subscriptionId)
        sub_items = (existing_sub.get("items") or {}).get("data") or []
        # Map existing line items onto the new prices (reuse item ids so Stripe
        # swaps the price in place rather than appending), honoring proration.
        update_items: list[dict[str, Any]] = []
        for idx, li in enumerate(line_items):
            entry: dict[str, Any] = dict(li)
            if idx < len(sub_items) and sub_items[idx].get("id"):
                entry["id"] = sub_items[idx]["id"]
            update_items.append(entry)

        updated = await opts.stripe_client.update_subscription(
            body.subscriptionId,
            items=update_items,
            proration_behavior=plan.proration_behavior,
            metadata={"referenceId": reference_id, "plan": plan.name},
        )

        now = int(time.time())
        await ctx.auth.adapter.update(
            model="subscription",
            where=(Where(field="stripeSubscriptionId", value=body.subscriptionId),),
            update={
                "plan": plan.name,
                "priceId": price_id,
                "billingInterval": billing_interval,
                "seats": body.seats,
                "status": updated.get("status", "active"),
                "updatedAt": now,
            },
        )
        return {
            "subscription": updated,
            "plan": plan.name,
            "redirect": False,
        }

    return create_auth_endpoint(
        "/subscription/upgrade",
        EndpointOptions(method="POST", body=UpgradeSubscriptionBody, requires_session=True),
        handler,
    )


def _build_list_endpoint(opts: StripeOptions) -> AuthEndpoint:
    async def handler(ctx: EndpointContext) -> dict[str, Any]:
        assert ctx.session is not None
        reference = (
            ctx.request.query.get("referenceId")
            if isinstance(ctx.request.query.get("referenceId"), str)
            else None
        ) or ctx.session.user_id
        rows = await ctx.auth.adapter.find_many(
            model="subscription",
            where=(Where(field="referenceId", value=reference),),
        )
        return {"subscriptions": list(rows)}

    return create_auth_endpoint(
        "/stripe/list-subscriptions",
        EndpointOptions(method="GET", requires_session=True),
        handler,
    )


# ----- webhook --------------------------------------------------------------


async def _persist_subscription(
    ctx: EndpointContext,
    *,
    stripe_sub: dict[str, Any],
    reference_id: str | None,
    plan_name: str | None,
) -> None:
    items = (stripe_sub.get("items") or {}).get("data") or []
    first_item = items[0] if items else {}
    period_start = first_item.get("current_period_start") or stripe_sub.get("current_period_start")
    period_end = first_item.get("current_period_end") or stripe_sub.get("current_period_end")
    now = int(time.time())
    existing = await ctx.auth.adapter.find_one(
        model="subscription",
        where=(Where(field="stripeSubscriptionId", value=stripe_sub["id"]),),
    )
    payload = {
        "stripeSubscriptionId": stripe_sub["id"],
        "stripeCustomerId": stripe_sub.get("customer"),
        "status": stripe_sub.get("status", "incomplete"),
        "plan": plan_name or (existing or {}).get("plan", "unknown"),
        "referenceId": reference_id or (existing or {}).get("referenceId", ""),
        "periodStart": period_start,
        "periodEnd": period_end,
        "cancelAtPeriodEnd": bool(stripe_sub.get("cancel_at_period_end")),
        "seats": first_item.get("quantity"),
        "trialStart": stripe_sub.get("trial_start"),
        "trialEnd": stripe_sub.get("trial_end"),
        "updatedAt": now,
    }
    if existing is None:
        payload["createdAt"] = now
        await ctx.auth.adapter.create(model="subscription", data=payload)
    else:
        await ctx.auth.adapter.update(
            model="subscription",
            where=(Where(field="id", value=existing["id"]),),
            update=payload,
        )


def _build_webhook_endpoint(opts: StripeOptions) -> AuthEndpoint:
    async def handler(ctx: EndpointContext) -> dict[str, Any]:
        sig = ctx.request.headers.get("stripe-signature")
        if not sig:
            raise APIError(400, "INVALID_SIGNATURE", message="missing Stripe-Signature header")
        payload = await ctx.request.body()
        verify_signature(payload, sig, opts.webhook_secret)
        try:
            event = json.loads(payload.decode("utf-8"))
        except Exception as e:
            raise APIError(400, "INVALID_REQUEST", message=str(e)) from None

        event_type = event.get("type", "")
        data_object = (event.get("data") or {}).get("object") or {}

        if event_type.startswith("customer.subscription."):
            metadata = data_object.get("metadata") or {}
            reference_id = metadata.get("referenceId")
            plan_name = metadata.get("plan")
            await _persist_subscription(
                ctx,
                stripe_sub=data_object,
                reference_id=reference_id,
                plan_name=plan_name,
            )
        elif event_type == "checkout.session.completed":
            sub_id = data_object.get("subscription")
            if sub_id:
                stripe_sub = await opts.stripe_client.get_subscription(sub_id)
                metadata = data_object.get("metadata") or {}
                await _persist_subscription(
                    ctx,
                    stripe_sub=stripe_sub,
                    reference_id=metadata.get("referenceId")
                    or data_object.get("client_reference_id"),
                    plan_name=metadata.get("plan"),
                )
        elif event_type in ("invoice.paid", "invoice.payment_failed"):
            sub_id = data_object.get("subscription")
            if sub_id:
                await ctx.auth.adapter.update(
                    model="subscription",
                    where=(Where(field="stripeSubscriptionId", value=sub_id),),
                    update={
                        "status": "active" if event_type == "invoice.paid" else "past_due",
                        "updatedAt": int(time.time()),
                    },
                )

        if opts.on_event is not None:
            try:
                await opts.on_event(event)  # type: ignore[arg-type]
            except Exception:
                pass

        return {"received": True}

    return create_auth_endpoint(
        "/stripe/webhook",
        EndpointOptions(method="POST"),
        handler,
    )


def build_endpoints(opts: StripeOptions) -> tuple[AuthEndpoint, ...]:
    """Construct every endpoint the plugin contributes, bound to `opts`."""
    return (
        _build_checkout_endpoint(opts),
        _build_billing_portal_endpoint(opts),
        _build_cancel_endpoint(opts),
        _build_resume_endpoint(opts),
        _build_upgrade_endpoint(opts),
        _build_list_endpoint(opts),
        _build_webhook_endpoint(opts),
    )


__all__ = ["build_endpoints"]
