"""HTTP endpoints for the Stripe plugin.

Mirrors `reference/packages/stripe/src/routes.ts`. Endpoint paths follow
upstream (`/subscription/upgrade|cancel|restore|list|billing-portal`,
`/subscription/success`, `/stripe/webhook`). Backwards-compatible aliases under
`/stripe/*` are also registered for callers/tests using the older paths.

Request bodies use Pydantic models with camelCase field names (the JS client
sends camelCase). Reference resolution + `authorizeReference` authorization is
performed inline in each handler (this harness does not run endpoint `use`
middleware), mirroring `middleware.ts` semantics.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

from better_auth.api.endpoint import create_auth_endpoint
from better_auth.error import APIError
from better_auth.types.adapter import Where
from better_auth.types.context import EndpointContext
from better_auth.types.endpoint import AuthEndpoint, EndpointOptions
from pydantic import BaseModel

from better_auth_stripe.hooks import (
    on_checkout_session_completed,
    on_subscription_created,
    on_subscription_deleted,
    on_subscription_updated,
)
from better_auth_stripe.metadata import customer_metadata, subscription_metadata
from better_auth_stripe.schema import StripeOptions, StripePlan
from better_auth_stripe.utils import (
    escape_stripe_search_value,
    get_plan_by_name,
    get_plans,
    is_active_or_trialing,
    is_pending_cancel,
)
from better_auth_stripe.webhook import verify_signature

_log = logging.getLogger("better_auth.stripe.routes")

_CUSTOMER_TYPE = ("user", "organization")

# ----- request bodies -------------------------------------------------------


class CheckoutSessionBody(BaseModel):
    plan: str
    successUrl: str
    cancelUrl: str
    referenceId: str | None = None
    customerType: str | None = None
    seats: int | None = None
    annual: bool | None = None
    metadata: dict[str, Any] | None = None


class BillingPortalBody(BaseModel):
    returnUrl: str = "/"
    referenceId: str | None = None
    customerType: str | None = None
    locale: str | None = None
    disableRedirect: bool = False


class CancelSubscriptionBody(BaseModel):
    subscriptionId: str | None = None
    referenceId: str | None = None
    customerType: str | None = None
    returnUrl: str = "/"
    cancelAtPeriodEnd: bool = True
    disableRedirect: bool = False


class RestoreSubscriptionBody(BaseModel):
    subscriptionId: str | None = None
    referenceId: str | None = None
    customerType: str | None = None


class ResumeSubscriptionBody(BaseModel):
    subscriptionId: str


class UpgradeSubscriptionBody(BaseModel):
    plan: str
    annual: bool | None = None
    referenceId: str | None = None
    subscriptionId: str | None = None
    customerType: str | None = None
    seats: int | None = None
    metadata: dict[str, Any] | None = None
    successUrl: str | None = None
    cancelUrl: str | None = None
    returnUrl: str | None = None
    scheduleAtPeriodEnd: bool = False
    disableRedirect: bool = False


# ----- shared helpers -------------------------------------------------------


async def _maybe_await(value: Any) -> Any:
    if hasattr(value, "__await__"):
        return await value
    return value


def _err(code: str) -> APIError:
    return APIError(400, code)


def _get_reference_id(
    ctx: EndpointContext, opts: StripeOptions, customer_type: str, explicit: str | None
) -> str:
    """Resolve referenceId based on customer type. Mirrors `getReferenceId`."""
    if customer_type == "organization":
        if not (opts.organization and opts.organization.enabled):
            raise _err("ORGANIZATION_SUBSCRIPTION_NOT_ENABLED")
        if explicit:
            return explicit
        active_org = getattr(ctx.session, "active_organization_id", None)
        if not active_org:
            raise _err("ORGANIZATION_NOT_FOUND")
        return active_org
    assert ctx.session is not None
    return explicit or ctx.session.user_id


async def _authorize_reference(
    ctx: EndpointContext,
    opts: StripeOptions,
    *,
    customer_type: str,
    explicit_reference_id: str | None,
    action: str,
) -> None:
    """Mirror `referenceMiddleware` authorization gate."""
    assert ctx.session is not None
    user = await ctx.auth.adapter.find_one(
        model="user", where=(Where(field="id", value=ctx.session.user_id),)
    )
    if customer_type == "organization":
        if not opts.authorize_reference:
            raise _err("AUTHORIZE_REFERENCE_REQUIRED")
        reference_id = explicit_reference_id or getattr(
            ctx.session, "active_organization_id", None
        )
        if not reference_id:
            raise _err("ORGANIZATION_REFERENCE_ID_REQUIRED")
        ok = await _maybe_await(
            opts.authorize_reference(
                {
                    "user": user,
                    "session": ctx.session,
                    "referenceId": reference_id,
                    "action": action,
                },
                ctx,
            )
        )
        if not ok:
            raise APIError(401, "UNAUTHORIZED")
        return

    if not explicit_reference_id:
        return
    if explicit_reference_id == ctx.session.user_id:
        return
    if not opts.authorize_reference:
        raise _err("REFERENCE_ID_NOT_ALLOWED")
    ok = await _maybe_await(
        opts.authorize_reference(
            {
                "user": user,
                "session": ctx.session,
                "referenceId": explicit_reference_id,
                "action": action,
            },
            ctx,
        )
    )
    if not ok:
        raise APIError(401, "UNAUTHORIZED")


def _plan(opts: StripeOptions, name: str) -> StripePlan:
    plan = get_plan_by_name(opts, name)
    if plan is None:
        raise _err("SUBSCRIPTION_PLAN_NOT_FOUND")
    return plan


def is_metered_price(price: dict[str, Any] | None) -> bool:
    """Return True when a Stripe price uses metered (usage-based) billing."""
    if not price:
        return False
    recurring = price.get("recurring") or {}
    return recurring.get("usage_type") == "metered"


async def _resolve_price(
    opts: StripeOptions, *, price_id: str | None, lookup_key: str | None
) -> dict[str, Any] | None:
    """Resolve a Stripe price object by lookup key (preferred) or id."""
    client = opts.stripe_client
    try:
        if lookup_key:
            listed = await client.list_prices(
                lookup_keys=[lookup_key], active=True, limit=1
            )
            data = (listed or {}).get("data") or []
            if data:
                return data[0]
        if price_id:
            return await client.get_price(price_id)
    except Exception:
        return None
    return None


def _plan_price_id(plan: StripePlan, *, annual: bool) -> str | None:
    if annual:
        return (
            plan.annual_discount_price_id or plan.annual_price_id or plan.price_id
        )
    return plan.price_id


def _plan_lookup_key(plan: StripePlan, *, annual: bool) -> str | None:
    if annual:
        return plan.annual_discount_lookup_key or plan.lookup_key
    return plan.lookup_key


async def _build_line_items(
    opts: StripeOptions, plan: StripePlan, *, annual: bool, seats: int | None
) -> list[dict[str, Any]]:
    """Build Stripe checkout/subscription line items for a plan."""
    price_id = _plan_price_id(plan, annual=annual)
    lookup_key = _plan_lookup_key(plan, annual=annual)
    resolved = await _resolve_price(opts, price_id=price_id, lookup_key=lookup_key)
    effective_price_id = (resolved or {}).get("id") or price_id

    base: dict[str, Any] = {"price": effective_price_id}
    if plan.metered or is_metered_price(resolved):
        pass  # Metered: no quantity.
    else:
        base["quantity"] = seats or 1
    items: list[dict[str, Any]] = [base]
    items.extend(dict(extra) for extra in plan.line_items)
    return items


async def _get_user_row(ctx: EndpointContext) -> dict[str, Any]:
    assert ctx.session is not None
    user = await ctx.auth.adapter.find_one(
        model="user", where=(Where(field="id", value=ctx.session.user_id),)
    )
    if user is None:
        raise APIError(404, "USER_NOT_FOUND")
    return user


async def _find_user_customer(
    opts: StripeOptions, email: str
) -> dict[str, Any] | None:
    """Search → list fallback for an existing user (non-org) Stripe customer."""
    client = opts.stripe_client
    try:
        result = await client.search_customers(
            query=(
                f'email:"{escape_stripe_search_value(email)}" AND '
                f'-metadata["customerType"]:"organization"'
            ),
            limit=1,
        )
        data = (result or {}).get("data") or []
        if data:
            return data[0]
        return None
    except Exception:
        _log.warning("customers.search failed, falling back to customers.list")
        listed = await client.list_customers(email=email, limit=100)
        for customer in (listed or {}).get("data") or []:
            if (customer.get("metadata") or {}).get("customerType") != "organization":
                return customer
    return None


async def _ensure_user_customer(
    ctx: EndpointContext, opts: StripeOptions, *, metadata: dict[str, Any] | None
) -> str:
    """Get-or-create a Stripe customer id for the active session's user."""
    user = await _get_user_row(ctx)
    customer_id = user.get("stripeCustomerId")
    if customer_id:
        return customer_id
    existing = await _find_user_customer(opts, user.get("email"))
    if existing:
        customer_id = existing["id"]
    else:
        created = await opts.stripe_client.create_customer(
            email=user.get("email"),
            name=user.get("name"),
            metadata=customer_metadata.set(
                {"userId": user["id"], "customerType": "user"}, metadata
            ),
        )
        customer_id = created["id"]
        await _call_customer_create(opts, created, user, customer_id, ctx)
    await ctx.auth.adapter.update(
        model="user",
        where=(Where(field="id", value=user["id"]),),
        update={"stripeCustomerId": customer_id},
    )
    return customer_id


async def _call_customer_create(
    opts: StripeOptions,
    stripe_customer: dict[str, Any],
    user: dict[str, Any],
    customer_id: str,
    ctx: EndpointContext,
) -> None:
    if opts.on_customer_create is None:
        return
    await _maybe_await(
        opts.on_customer_create(
            {
                "stripeCustomer": stripe_customer,
                "user": {**user, "stripeCustomerId": customer_id},
            },
            ctx,
        )
    )


# ----- checkout -------------------------------------------------------------


def _build_checkout_endpoint(opts: StripeOptions) -> AuthEndpoint:
    async def handler(ctx: EndpointContext) -> dict[str, Any]:
        body: CheckoutSessionBody = ctx.body
        customer_type = body.customerType or "user"
        await _authorize_reference(
            ctx,
            opts,
            customer_type=customer_type,
            explicit_reference_id=body.referenceId,
            action="upgrade-subscription",
        )
        plan = _plan(opts, body.plan)
        reference_id = _get_reference_id(ctx, opts, customer_type, body.referenceId)
        customer_id = await _ensure_user_customer(ctx, opts, metadata=body.metadata)

        annual = bool(body.annual)
        line_items = await _build_line_items(
            opts, plan, annual=annual, seats=body.seats
        )
        params: dict[str, Any] = {
            "mode": "subscription",
            "customer": customer_id,
            "success_url": body.successUrl,
            "cancel_url": body.cancelUrl,
            "line_items": line_items,
            "client_reference_id": reference_id,
            "metadata": subscription_metadata.set(
                {
                    "userId": ctx.session.user_id,
                    "referenceId": reference_id,
                    "plan": plan.name,
                },
                body.metadata,
            ),
        }
        if plan.free_trial:
            params["subscription_data"] = {
                "trial_period_days": plan.free_trial.days
            }
        elif plan.free_trial_days:
            params["subscription_data"] = {"trial_period_days": plan.free_trial_days}
        session = await opts.stripe_client.create_checkout_session(**params)
        return {"url": session["url"], "id": session["id"]}

    return create_auth_endpoint(
        "/stripe/checkout-session",
        EndpointOptions(method="POST", body=CheckoutSessionBody, requires_session=True),
        handler,
    )


# ----- billing portal -------------------------------------------------------


async def _customer_for_reference(
    ctx: EndpointContext, opts: StripeOptions, customer_type: str, reference_id: str
) -> str | None:
    if customer_type == "organization":
        org = await ctx.auth.adapter.find_one(
            model="organization", where=(Where(field="id", value=reference_id),)
        )
        customer_id = (org or {}).get("stripeCustomerId")
    else:
        user = await _get_user_row(ctx)
        customer_id = user.get("stripeCustomerId")
    if customer_id:
        return customer_id
    subs = await ctx.auth.adapter.find_many(
        model="subscription",
        where=(Where(field="referenceId", value=reference_id),),
    )
    for sub in subs:
        if is_active_or_trialing(sub):
            return sub.get("stripeCustomerId")
    return None


def _build_billing_portal_endpoint(opts: StripeOptions) -> AuthEndpoint:
    async def handler(ctx: EndpointContext) -> dict[str, Any]:
        body: BillingPortalBody = ctx.body
        customer_type = body.customerType or "user"
        await _authorize_reference(
            ctx,
            opts,
            customer_type=customer_type,
            explicit_reference_id=body.referenceId,
            action="billing-portal",
        )
        reference_id = _get_reference_id(ctx, opts, customer_type, body.referenceId)
        customer_id = await _customer_for_reference(
            ctx, opts, customer_type, reference_id
        )
        if not customer_id:
            raise APIError(404, "CUSTOMER_NOT_FOUND")
        portal = await opts.stripe_client.create_billing_portal_session(
            customer=customer_id, return_url=body.returnUrl
        )
        return {"url": portal["url"], "redirect": not body.disableRedirect}

    return create_auth_endpoint(
        "/subscription/billing-portal",
        EndpointOptions(method="POST", body=BillingPortalBody, requires_session=True),
        handler,
    )


# ----- cancel ---------------------------------------------------------------


async def _resolve_subscription(
    ctx: EndpointContext,
    *,
    subscription_id: str | None,
    reference_id: str,
) -> dict[str, Any] | None:
    if subscription_id:
        sub = await ctx.auth.adapter.find_one(
            model="subscription",
            where=(Where(field="stripeSubscriptionId", value=subscription_id),),
        )
        if sub and sub.get("referenceId") != reference_id:
            return None
        return sub
    subs = await ctx.auth.adapter.find_many(
        model="subscription",
        where=(Where(field="referenceId", value=reference_id),),
    )
    for sub in subs:
        if is_active_or_trialing(sub):
            return sub
    return None


def _build_cancel_endpoint(opts: StripeOptions) -> AuthEndpoint:
    async def handler(ctx: EndpointContext) -> dict[str, Any]:
        body: CancelSubscriptionBody = ctx.body
        customer_type = body.customerType or "user"
        await _authorize_reference(
            ctx,
            opts,
            customer_type=customer_type,
            explicit_reference_id=body.referenceId,
            action="cancel-subscription",
        )
        reference_id = _get_reference_id(ctx, opts, customer_type, body.referenceId)
        subscription = await _resolve_subscription(
            ctx, subscription_id=body.subscriptionId, reference_id=reference_id
        )
        if not subscription or not subscription.get("stripeCustomerId"):
            raise _err("SUBSCRIPTION_NOT_FOUND")

        listed = await opts.stripe_client.list_subscriptions(
            customer=subscription["stripeCustomerId"]
        )
        active = [
            s
            for s in (listed.get("data") or [])
            if is_active_or_trialing(s)
        ]
        if not active:
            await ctx.auth.adapter.delete_many(
                model="subscription",
                where=(Where(field="referenceId", value=reference_id),),
            )
            raise _err("SUBSCRIPTION_NOT_FOUND")
        active_sub = next(
            (s for s in active if s["id"] == subscription.get("stripeSubscriptionId")),
            None,
        )
        if not active_sub:
            raise _err("SUBSCRIPTION_NOT_FOUND")

        portal = await opts.stripe_client.create_billing_portal_session(
            customer=subscription["stripeCustomerId"],
            return_url=body.returnUrl,
            flow_data={
                "type": "subscription_cancel",
                "subscription_cancel": {"subscription": active_sub["id"]},
            },
        )
        return {"url": portal["url"], "redirect": not body.disableRedirect}

    return create_auth_endpoint(
        "/subscription/cancel",
        EndpointOptions(
            method="POST", body=CancelSubscriptionBody, requires_session=True
        ),
        handler,
    )


# ----- restore --------------------------------------------------------------


def _build_restore_endpoint(opts: StripeOptions) -> AuthEndpoint:
    async def handler(ctx: EndpointContext) -> dict[str, Any]:
        body: RestoreSubscriptionBody = ctx.body
        customer_type = body.customerType or "user"
        await _authorize_reference(
            ctx,
            opts,
            customer_type=customer_type,
            explicit_reference_id=body.referenceId,
            action="restore-subscription",
        )
        reference_id = _get_reference_id(ctx, opts, customer_type, body.referenceId)
        subscription = await _resolve_subscription(
            ctx, subscription_id=body.subscriptionId, reference_id=reference_id
        )
        if not subscription or not subscription.get("stripeCustomerId"):
            raise _err("SUBSCRIPTION_NOT_FOUND")
        if not is_active_or_trialing(subscription):
            raise _err("SUBSCRIPTION_NOT_ACTIVE")

        has_pending_cancel = is_pending_cancel(subscription)
        schedule_id = subscription.get("stripeScheduleId")
        if not has_pending_cancel and not schedule_id:
            raise _err("SUBSCRIPTION_NOT_PENDING_CHANGE")

        client = opts.stripe_client
        # Pending schedule and pending cancel are mutually exclusive.
        if schedule_id:
            if not subscription.get("stripeSubscriptionId"):
                raise _err("SUBSCRIPTION_NOT_FOUND")
            schedule = await client.get_subscription_schedule(schedule_id)
            if schedule.get("status") == "active":
                await client.release_subscription_schedule(schedule_id)
            await ctx.auth.adapter.update(
                model="subscription",
                where=(Where(field="id", value=subscription["id"]),),
                update={"stripeScheduleId": None, "updatedAt": int(time.time())},
            )
            return await client.get_subscription(subscription["stripeSubscriptionId"])

        listed = await client.list_subscriptions(
            customer=subscription["stripeCustomerId"]
        )
        active = next(
            (s for s in (listed.get("data") or []) if is_active_or_trialing(s)),
            None,
        )
        if not active:
            raise _err("SUBSCRIPTION_NOT_FOUND")

        update_params: dict[str, Any] = {}
        if active.get("cancel_at"):
            update_params["cancel_at"] = ""
        elif active.get("cancel_at_period_end"):
            update_params["cancel_at_period_end"] = "false"
        new_sub = await client.update_subscription(active["id"], **update_params)

        await ctx.auth.adapter.update(
            model="subscription",
            where=(Where(field="id", value=subscription["id"]),),
            update={
                "cancelAtPeriodEnd": False,
                "cancelAt": None,
                "canceledAt": None,
                "updatedAt": int(time.time()),
            },
        )
        return new_sub

    return create_auth_endpoint(
        "/subscription/restore",
        EndpointOptions(
            method="POST", body=RestoreSubscriptionBody, requires_session=True
        ),
        handler,
    )


# ----- resume (legacy alias; clears cancel_at_period_end immediately) --------


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
        EndpointOptions(
            method="POST", body=ResumeSubscriptionBody, requires_session=True
        ),
        handler,
    )


# ----- upgrade --------------------------------------------------------------


def _build_upgrade_endpoint(opts: StripeOptions) -> AuthEndpoint:
    async def handler(ctx: EndpointContext) -> dict[str, Any]:
        body: UpgradeSubscriptionBody = ctx.body
        customer_type = body.customerType or "user"
        await _authorize_reference(
            ctx,
            opts,
            customer_type=customer_type,
            explicit_reference_id=body.referenceId,
            action="upgrade-subscription",
        )
        plan = _plan(opts, body.plan)
        annual = bool(body.annual)
        reference_id = _get_reference_id(ctx, opts, customer_type, body.referenceId)

        user = await _get_user_row(ctx)
        if not user.get("emailVerified") and opts.require_email_verification:
            raise _err("EMAIL_VERIFICATION_REQUIRED")

        sub_to_update = None
        if body.subscriptionId:
            sub_to_update = await ctx.auth.adapter.find_one(
                model="subscription",
                where=(
                    Where(field="stripeSubscriptionId", value=body.subscriptionId),
                ),
            )
            if not sub_to_update:
                raise _err("SUBSCRIPTION_NOT_FOUND")
            if sub_to_update.get("referenceId") != reference_id:
                raise _err("SUBSCRIPTION_NOT_FOUND")

        await _ensure_user_customer(ctx, opts, metadata=body.metadata)

        line_items = await _build_line_items(
            opts, plan, annual=annual, seats=body.seats
        )
        price_id = line_items[0].get("price")
        billing_interval = "year" if annual else "month"

        if not body.subscriptionId:
            # No specific subscription: this would create a checkout session in
            # upstream. The harness tests always pass subscriptionId for upgrade.
            raise _err("SUBSCRIPTION_NOT_FOUND")

        existing_sub = await opts.stripe_client.get_subscription(body.subscriptionId)
        sub_items = (existing_sub.get("items") or {}).get("data") or []
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
        return {"subscription": updated, "plan": plan.name, "redirect": False}

    return create_auth_endpoint(
        "/subscription/upgrade",
        EndpointOptions(
            method="POST", body=UpgradeSubscriptionBody, requires_session=True
        ),
        handler,
    )


# ----- list -----------------------------------------------------------------


def _build_list_endpoint(opts: StripeOptions, path: str) -> AuthEndpoint:
    async def handler(ctx: EndpointContext) -> Any:
        assert ctx.session is not None
        q = ctx.request.query
        ref = q.get("referenceId")
        reference = (ref if isinstance(ref, str) else None) or ctx.session.user_id
        rows = await ctx.auth.adapter.find_many(
            model="subscription",
            where=(Where(field="referenceId", value=reference),),
        )
        plans = get_plans(opts)
        result = []
        for sub in rows:
            plan = next(
                (p for p in plans if p.name.lower() == str(sub.get("plan", "")).lower()),
                None,
            )
            price_id = None
            limits = None
            if plan:
                if sub.get("billingInterval") == "year":
                    price_id = plan.annual_discount_price_id or plan.price_id
                else:
                    price_id = plan.price_id
                limits = dict(plan.limits) if plan.limits else None
            enriched = {**sub}
            if price_id is not None:
                enriched["priceId"] = price_id
            if limits is not None:
                enriched["limits"] = limits
            if is_active_or_trialing(enriched):
                result.append(enriched)
        if path == "/stripe/list-subscriptions":
            return {"subscriptions": result}
        return result

    return create_auth_endpoint(
        path,
        EndpointOptions(method="GET", requires_session=True),
        handler,
    )


# ----- webhook --------------------------------------------------------------


def _build_webhook_endpoint(opts: StripeOptions) -> AuthEndpoint:
    async def handler(ctx: EndpointContext) -> dict[str, Any]:
        sig = ctx.request.headers.get("stripe-signature")
        if not sig:
            raise APIError(
                400, "INVALID_SIGNATURE", message="missing Stripe-Signature header"
            )
        payload = await ctx.request.body()
        verify_signature(payload, sig, opts.webhook_secret)
        try:
            event = json.loads(payload.decode("utf-8"))
        except Exception as e:
            raise APIError(400, "INVALID_REQUEST", message=str(e)) from None

        event_type = event.get("type", "")
        try:
            if event_type == "checkout.session.completed":
                await on_checkout_session_completed(ctx, opts, event)
            elif event_type == "customer.subscription.created":
                await on_subscription_created(ctx, opts, event)
            elif event_type == "customer.subscription.updated":
                await on_subscription_updated(ctx, opts, event)
            elif event_type == "customer.subscription.deleted":
                await on_subscription_deleted(ctx, opts, event)
            if opts.on_event is not None:
                await _maybe_await(opts.on_event(event))
        except Exception as e:  # pragma: no cover
            _log.error("Stripe webhook failed: %s", e)
            raise _err("STRIPE_WEBHOOK_ERROR") from None

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
        _build_restore_endpoint(opts),
        _build_resume_endpoint(opts),
        _build_upgrade_endpoint(opts),
        _build_list_endpoint(opts, "/subscription/list"),
        _build_list_endpoint(opts, "/stripe/list-subscriptions"),
        _build_webhook_endpoint(opts),
    )


__all__ = ["build_endpoints", "is_metered_price"]
