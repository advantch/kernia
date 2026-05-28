"""HTTP endpoints for the Stripe plugin.

Mirrors `reference/packages/stripe/src/routes.ts` at a Python-port granularity:
just enough surface to support a complete checkout → webhook → subscription
lifecycle through the test driver.
"""

from __future__ import annotations

import json
import time
from typing import Any

from pydantic import BaseModel

from kernia.api.endpoint import create_auth_endpoint
from kernia.error import APIError
from kernia.types.adapter import Where
from kernia.types.context import EndpointContext
from kernia.types.endpoint import AuthEndpoint, EndpointOptions
from kernia_stripe.schema import StripeOptions, StripePlan
from kernia_stripe.webhook import verify_signature


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


class BillingCheckBody(BaseModel):
    feature: str
    referenceId: str | None = None
    required: int = 1


class BillingTrackBody(BaseModel):
    feature: str
    referenceId: str | None = None
    quantity: int = 1
    properties: dict[str, Any] | None = None


# ----- helpers --------------------------------------------------------------


def _plan(opts: StripeOptions, name: str) -> StripePlan:
    plan = opts.plans.get(name)
    if plan is None:
        raise APIError(400, "PLAN_NOT_FOUND", message=f"Unknown plan: {name}")
    return plan


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


async def _upsert_by(
    ctx: EndpointContext,
    *,
    model: str,
    field: str,
    value: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    existing = await ctx.auth.adapter.find_one(
        model=model,
        where=(Where(field=field, value=value),),
    )
    if existing is None:
        return await ctx.auth.adapter.create(model=model, data=payload)
    return await ctx.auth.adapter.update(
        model=model,
        where=(Where(field="id", value=existing["id"]),),
        update=payload,
    ) or existing


def _json(value: Any) -> str:
    return json.dumps(value or {}, sort_keys=True)


async def _billing_reference(ctx: EndpointContext, body_ref: str | None = None) -> str:
    if body_ref:
        return body_ref
    if ctx.session is None:
        raise APIError(401, "UNAUTHORIZED")
    return ctx.session.user_id


# ----- handlers -------------------------------------------------------------


def _build_checkout_endpoint(opts: StripeOptions) -> AuthEndpoint:
    async def handler(ctx: EndpointContext) -> dict[str, Any]:
        body: CheckoutSessionBody = ctx.body
        plan = _plan(opts, body.plan)
        reference_id = _reference_id(ctx, opts, body.referenceId)
        customer_id = await _ensure_customer(ctx, opts)

        line_items: list[dict[str, Any]] = [
            {"price": plan.price_id, "quantity": body.seats or 1},
        ]
        session = await opts.stripe_client.create_checkout_session(
            mode="subscription",
            customer=customer_id,
            success_url=body.successUrl,
            cancel_url=body.cancelUrl,
            line_items=line_items,
            client_reference_id=reference_id,
            metadata={"referenceId": reference_id, "plan": plan.name},
        )
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


def _build_catalog_sync_endpoint(opts: StripeOptions) -> AuthEndpoint:
    async def handler(ctx: EndpointContext) -> dict[str, Any]:
        products = (await opts.stripe_client.list_products()).get("data", [])
        prices = (await opts.stripe_client.list_prices()).get("data", [])
        now = int(time.time())
        for product in products:
            await _upsert_by(
                ctx,
                model="billingProduct",
                field="stripeProductId",
                value=product["id"],
                payload={
                    "stripeProductId": product["id"],
                    "name": product.get("name") or product["id"],
                    "active": bool(product.get("active", True)),
                    "metadata": _json(product.get("metadata")),
                    "createdAt": now,
                    "updatedAt": now,
                },
            )
        for price in prices:
            recurring = price.get("recurring") or {}
            await _upsert_by(
                ctx,
                model="billingPrice",
                field="stripePriceId",
                value=price["id"],
                payload={
                    "stripePriceId": price["id"],
                    "stripeProductId": str(price.get("product") or ""),
                    "currency": price.get("currency") or "usd",
                    "unitAmount": price.get("unit_amount"),
                    "interval": recurring.get("interval"),
                    "lookupKey": price.get("lookup_key"),
                    "active": bool(price.get("active", True)),
                    "metadata": _json(price.get("metadata")),
                    "createdAt": now,
                    "updatedAt": now,
                },
            )
        await _upsert_by(
            ctx,
            model="billingSyncState",
            field="source",
            value="stripe",
            payload={
                "source": "stripe",
                "status": "success",
                "message": f"Imported {len(products)} products and {len(prices)} prices.",
                "syncedAt": now,
            },
        )
        return {"products": len(products), "prices": len(prices)}

    return create_auth_endpoint(
        "/stripe/catalog/sync",
        EndpointOptions(method="POST", requires_session=True),
        handler,
    )


def _build_products_endpoint() -> AuthEndpoint:
    async def handler(ctx: EndpointContext) -> dict[str, Any]:
        rows = await ctx.auth.adapter.find_many(model="billingProduct")
        return {"products": list(rows)}

    return create_auth_endpoint(
        "/stripe/products",
        EndpointOptions(method="GET", requires_session=True),
        handler,
    )


def _build_prices_endpoint() -> AuthEndpoint:
    async def handler(ctx: EndpointContext) -> dict[str, Any]:
        rows = await ctx.auth.adapter.find_many(model="billingPrice")
        return {"prices": list(rows)}

    return create_auth_endpoint(
        "/stripe/prices",
        EndpointOptions(method="GET", requires_session=True),
        handler,
    )


def _build_billing_check_endpoint() -> AuthEndpoint:
    async def handler(ctx: EndpointContext) -> dict[str, Any]:
        body: BillingCheckBody = ctx.body
        reference = await _billing_reference(ctx, body.referenceId)
        ent = await ctx.auth.adapter.find_one(
            model="billingEntitlement",
            where=(
                Where(field="referenceId", value=reference),
                Where(field="featureKey", value=body.feature),
            ),
        )
        if ent is None:
            return {
                "allowed": False,
                "referenceId": reference,
                "feature": body.feature,
                "reason": "missing_entitlement",
            }
        included = int(ent.get("included") or 0)
        used = int(ent.get("used") or 0)
        unlimited = bool(ent.get("unlimited"))
        overage = bool(ent.get("overageAllowed"))
        remaining = None if unlimited else max(included - used, 0)
        allowed = unlimited or overage or (remaining is not None and remaining >= body.required)
        return {
            "allowed": allowed,
            "referenceId": reference,
            "feature": body.feature,
            "included": included,
            "used": used,
            "remaining": remaining,
            "unlimited": unlimited,
            "overageAllowed": overage,
        }

    return create_auth_endpoint(
        "/billing/check",
        EndpointOptions(method="POST", body=BillingCheckBody, requires_session=True),
        handler,
    )


def _build_billing_track_endpoint() -> AuthEndpoint:
    async def handler(ctx: EndpointContext) -> dict[str, Any]:
        body: BillingTrackBody = ctx.body
        reference = await _billing_reference(ctx, body.referenceId)
        now = int(time.time())
        event = await ctx.auth.adapter.create(
            model="billingUsageEvent",
            data={
                "referenceId": reference,
                "featureKey": body.feature,
                "quantity": body.quantity,
                "properties": _json(body.properties),
                "createdAt": now,
            },
        )
        ent = await ctx.auth.adapter.find_one(
            model="billingEntitlement",
            where=(
                Where(field="referenceId", value=reference),
                Where(field="featureKey", value=body.feature),
            ),
        )
        if ent is not None:
            used = int(ent.get("used") or 0) + body.quantity
            await ctx.auth.adapter.update(
                model="billingEntitlement",
                where=(Where(field="id", value=ent["id"]),),
                update={"used": used, "updatedAt": now},
            )
        check = await _call_check(ctx, reference=reference, feature=body.feature)
        return {"event": event, "entitlement": check}

    return create_auth_endpoint(
        "/billing/track",
        EndpointOptions(method="POST", body=BillingTrackBody, requires_session=True),
        handler,
    )


async def _call_check(ctx: EndpointContext, *, reference: str, feature: str) -> dict[str, Any]:
    ent = await ctx.auth.adapter.find_one(
        model="billingEntitlement",
        where=(
            Where(field="referenceId", value=reference),
            Where(field="featureKey", value=feature),
        ),
    )
    if ent is None:
        return {"allowed": False, "referenceId": reference, "feature": feature}
    included = int(ent.get("included") or 0)
    used = int(ent.get("used") or 0)
    unlimited = bool(ent.get("unlimited"))
    remaining = None if unlimited else max(included - used, 0)
    return {
        "allowed": unlimited or bool(ent.get("overageAllowed")) or (remaining or 0) > 0,
        "referenceId": reference,
        "feature": feature,
        "included": included,
        "used": used,
        "remaining": remaining,
        "unlimited": unlimited,
    }


def _build_billing_customer_endpoint(opts: StripeOptions) -> AuthEndpoint:
    async def handler(ctx: EndpointContext) -> dict[str, Any]:
        assert ctx.session is not None
        customer_id = await _ensure_customer(ctx, opts)
        user = await ctx.auth.adapter.find_one(
            model="user",
            where=(Where(field="id", value=ctx.session.user_id),),
        )
        now = int(time.time())
        row = await _upsert_by(
            ctx,
            model="billingCustomer",
            field="referenceId",
            value=ctx.session.user_id,
            payload={
                "referenceId": ctx.session.user_id,
                "stripeCustomerId": customer_id,
                "email": (user or {}).get("email"),
                "name": (user or {}).get("name"),
                "createdAt": now,
                "updatedAt": now,
            },
        )
        return {"customer": row}

    return create_auth_endpoint(
        "/billing/customer",
        EndpointOptions(method="GET", requires_session=True),
        handler,
    )


def _build_billing_portal_alias(opts: StripeOptions) -> AuthEndpoint:
    async def handler(ctx: EndpointContext) -> dict[str, Any]:
        customer_id = await _ensure_customer(ctx, opts)
        return_url = (
            ctx.request.query.get("returnUrl")
            if isinstance(ctx.request.query.get("returnUrl"), str)
            else ctx.auth.base_url
        )
        portal = await opts.stripe_client.create_billing_portal_session(
            customer=customer_id,
            return_url=return_url,
        )
        return {"url": portal["url"]}

    return create_auth_endpoint(
        "/billing/portal",
        EndpointOptions(method="GET", requires_session=True),
        handler,
    )


def _build_billing_usage_endpoint() -> AuthEndpoint:
    async def handler(ctx: EndpointContext) -> dict[str, Any]:
        reference = await _billing_reference(
            ctx,
            ctx.request.query.get("referenceId")
            if isinstance(ctx.request.query.get("referenceId"), str)
            else None,
        )
        rows = await ctx.auth.adapter.find_many(
            model="billingUsageEvent",
            where=(Where(field="referenceId", value=reference),),
        )
        return {"usage": list(rows)}

    return create_auth_endpoint(
        "/billing/usage",
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
        _build_list_endpoint(opts),
        _build_catalog_sync_endpoint(opts),
        _build_products_endpoint(),
        _build_prices_endpoint(),
        _build_billing_check_endpoint(),
        _build_billing_track_endpoint(),
        _build_billing_customer_endpoint(opts),
        _build_billing_portal_alias(opts),
        _build_billing_usage_endpoint(),
        _build_webhook_endpoint(opts),
    )


__all__ = ["build_endpoints"]
