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

from kernia.api.endpoint import create_auth_endpoint
from kernia.error import APIError
from kernia.types.adapter import Where
from kernia.types.context import EndpointContext
from kernia.types.endpoint import AuthEndpoint, EndpointOptions
from pydantic import BaseModel

from kernia_stripe.hooks import (
    on_checkout_session_completed,
    on_subscription_created,
    on_subscription_deleted,
    on_subscription_updated,
)
from kernia_stripe.metadata import customer_metadata, subscription_metadata
from kernia_stripe.schema import StripeOptions, StripePlan
from kernia_stripe.utils import (
    escape_stripe_search_value,
    get_plan_by_name,
    get_plans,
    is_active_or_trialing,
    is_pending_cancel,
    resolve_plan_item,
)
from kernia_stripe.webhook import verify_signature

_log = logging.getLogger("kernia.stripe.routes")

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
    locale: str | None = None
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


async def _seat_member_count(
    ctx: EndpointContext,
    plan: StripePlan,
    *,
    customer_type: str,
    reference_id: str,
) -> int:
    """Member count for an org plan with auto-managed seats (else 0)."""
    if not (plan.seat_price_id and customer_type == "organization"):
        return 0
    return await ctx.auth.adapter.count(
        model="member",
        where=(Where(field="organizationId", value=reference_id),),
    )


async def _build_line_items(
    opts: StripeOptions,
    plan: StripePlan,
    *,
    annual: bool,
    seats: int | None,
    customer_type: str = "user",
    member_count: int = 0,
) -> list[dict[str, Any]]:
    """Build Stripe checkout/subscription line items for a plan.

    Mirrors upstream's seat-aware line-item assembly:
      * base price (skipped when the plan is seat-only, i.e. ``priceId ==
        seatPriceId``); quantity is 1 under auto-managed seats, else ``seats``,
        and omitted entirely for metered prices,
      * a per-seat line item priced at ``seatPriceId`` with ``quantity ==
        memberCount`` for org plans with auto-managed seats,
      * any plan-declared additional ``line_items`` (add-ons / metered) appended
        verbatim.
    """
    price_id = _plan_price_id(plan, annual=annual)
    lookup_key = _plan_lookup_key(plan, annual=annual)
    resolved = await _resolve_price(opts, price_id=price_id, lookup_key=lookup_key)
    effective_price_id = (resolved or {}).get("id") or price_id
    metered = plan.metered or is_metered_price(resolved)

    is_auto_managed_seats = bool(
        plan.seat_price_id and customer_type == "organization"
    )
    is_seat_only = is_auto_managed_seats and plan.seat_price_id == plan.price_id

    items: list[dict[str, Any]] = []
    if not is_seat_only:
        base: dict[str, Any] = {"price": effective_price_id}
        if not metered:
            base["quantity"] = 1 if is_auto_managed_seats else (seats or 1)
        items.append(base)
    if is_auto_managed_seats:
        items.append({"price": plan.seat_price_id, "quantity": member_count})
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


async def _find_org_customer(
    opts: StripeOptions, org_id: str
) -> dict[str, Any] | None:
    """Search → list fallback for an existing organization Stripe customer."""
    client = opts.stripe_client
    try:
        result = await client.search_customers(
            query=(
                f'metadata["organizationId"]:"{escape_stripe_search_value(org_id)}"'
                f' AND metadata["customerType"]:"organization"'
            ),
            limit=1,
        )
        data = (result or {}).get("data") or []
        if data:
            return data[0]
        return None
    except Exception:
        _log.warning("customers.search failed, falling back to customers.list")
        listed = await client.list_customers(limit=100)
        for customer in (listed or {}).get("data") or []:
            meta = customer.get("metadata") or {}
            if (
                meta.get("organizationId") == org_id
                and meta.get("customerType") == "organization"
            ):
                return customer
    return None


async def _ensure_org_customer(
    ctx: EndpointContext,
    opts: StripeOptions,
    *,
    reference_id: str,
    metadata: dict[str, Any] | None,
) -> str:
    """Get-or-create the Stripe customer id for an organization reference.

    Mirrors upstream's organization branch: look the org up (raising
    ``ORGANIZATION_NOT_FOUND`` when absent), reuse its ``stripeCustomerId`` if
    set, otherwise reconcile against any existing org-typed Stripe customer
    (search→list) before creating a fresh one named after the org. The plan's
    ``getCustomerCreateParams`` is merged with library-owned ``name``/``metadata``
    winning (defu semantics), and ``onCustomerCreate`` fires only for newly
    created customers. Any failure surfaces as ``UNABLE_TO_CREATE_CUSTOMER``.
    """
    org = await ctx.auth.adapter.find_one(
        model="organization", where=(Where(field="id", value=reference_id),)
    )
    if not org:
        raise _err("ORGANIZATION_NOT_FOUND")
    customer_id = org.get("stripeCustomerId")
    if customer_id:
        return customer_id
    try:
        stripe_customer = await _find_org_customer(opts, org["id"])
        if not stripe_customer:
            extra: dict[str, Any] = {}
            if opts.organization and opts.organization.get_customer_create_params:
                extra = (
                    await _maybe_await(
                        opts.organization.get_customer_create_params(org, ctx)
                    )
                    or {}
                )
            extra = dict(extra)
            # Library-owned fields take priority (defu: base wins).
            extra.pop("name", None)
            extra.pop("metadata", None)
            email = extra.pop("email", None)
            stripe_customer = await opts.stripe_client.create_customer(
                email=email,
                name=org.get("name"),
                metadata=customer_metadata.set(
                    {
                        "organizationId": org["id"],
                        "customerType": "organization",
                    },
                    metadata,
                ),
                **extra,
            )
            if opts.organization and opts.organization.on_customer_create:
                await _maybe_await(
                    opts.organization.on_customer_create(
                        {
                            "stripeCustomer": stripe_customer,
                            "organization": {
                                **org,
                                "stripeCustomerId": stripe_customer["id"],
                            },
                        },
                        ctx,
                    )
                )
        await ctx.auth.adapter.update(
            model="organization",
            where=(Where(field="id", value=org["id"]),),
            update={"stripeCustomerId": stripe_customer["id"]},
        )
        return stripe_customer["id"]
    except APIError:
        raise
    except Exception as e:
        _log.error("Organization customer creation failed: %s", e)
        raise _err("UNABLE_TO_CREATE_CUSTOMER") from e


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
        member_count = await _seat_member_count(
            ctx, plan, customer_type=customer_type, reference_id=reference_id
        )
        line_items = await _build_line_items(
            opts,
            plan,
            annual=annual,
            seats=body.seats,
            customer_type=customer_type,
            member_count=member_count,
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

        # For organization upgrades the active subscription lives on the org's
        # Stripe customer, not the acting user's. Resolve that first so the
        # active-subscription lookup below queries the right customer; fall back
        # to the user customer (creating one) when the org has none yet.
        customer_id: str | None = None
        if customer_type == "organization":
            customer_id = (
                sub_to_update.get("stripeCustomerId") if sub_to_update else None
            ) or await _customer_for_reference(
                ctx, opts, customer_type, reference_id
            )
            if not customer_id:
                customer_id = await _ensure_org_customer(
                    ctx, opts, reference_id=reference_id, metadata=body.metadata
                )
        else:
            customer_id = await _ensure_user_customer(
                ctx, opts, metadata=body.metadata
            )

        member_count = await _seat_member_count(
            ctx, plan, customer_type=customer_type, reference_id=reference_id
        )
        line_items = await _build_line_items(
            opts,
            plan,
            annual=annual,
            seats=body.seats,
            customer_type=customer_type,
            member_count=member_count,
        )
        price_id = line_items[0].get("price")
        billing_interval = "year" if annual else "month"

        # Resolve the active Stripe subscription (if any) to decide between the
        # in-place proration update path and the new-checkout-session path.
        target_stripe_sub_id = body.subscriptionId
        if not target_stripe_sub_id and sub_to_update is None:
            try:
                listed = await opts.stripe_client.list_subscriptions(
                    customer=customer_id
                )
            except Exception:
                listed = {"data": []}
            active = [
                s
                for s in (listed or {}).get("data") or []
                if s.get("status") in ("active", "trialing")
            ]
            # Only adopt an active Stripe subscription that maps to a DB row for
            # this referenceId (avoid mixing personal/org subscriptions).
            for s in active:
                db_row = await ctx.auth.adapter.find_one(
                    model="subscription",
                    where=(
                        Where(field="stripeSubscriptionId", value=s.get("id")),
                        Where(field="referenceId", value=reference_id),
                    ),
                )
                if db_row is not None:
                    target_stripe_sub_id = s.get("id")
                    break

        # When a subscriptionId is supplied it may point at an *incomplete* DB
        # row that has no live Stripe subscription yet (e.g. a checkout never
        # completed). Retrieve it and only take the in-place proration path when
        # Stripe reports it active/trialing; otherwise fall through to checkout.
        existing_sub: dict[str, Any] | None = None
        if target_stripe_sub_id:
            try:
                existing_sub = await opts.stripe_client.get_subscription(
                    target_stripe_sub_id
                )
            except Exception:
                existing_sub = None
            if not existing_sub or not is_active_or_trialing(existing_sub):
                existing_sub = None
                target_stripe_sub_id = None

        if not target_stripe_sub_id or existing_sub is None:
            # No active subscription to prorate against: create (or reuse) an
            # `incomplete` subscription row and open a Stripe Checkout session.
            return await _upgrade_via_checkout(
                ctx,
                opts,
                plan=plan,
                reference_id=reference_id,
                customer_id=customer_id,
                customer_type=customer_type,
                line_items=line_items,
                billing_interval=billing_interval,
                body=body,
            )

        # The DB row backing this Stripe subscription (for schedule bookkeeping).
        db_row = await ctx.auth.adapter.find_one(
            model="subscription",
            where=(Where(field="stripeSubscriptionId", value=target_stripe_sub_id),),
        )

        # Release any existing *plugin-created* subscription schedule attached to
        # this subscription before applying any plan change. Schedules created
        # outside the plugin (no `source: @better-auth/stripe` metadata) are left
        # untouched. Only probe when a schedule is actually attached.
        if existing_sub.get("schedule"):
            listed_scheds = await opts.stripe_client.list_subscription_schedules(
                customer=customer_id
            )
            for s in (listed_scheds or {}).get("data") or []:
                sub_ref = s.get("subscription")
                sub_ref_id = (
                    sub_ref.get("id") if isinstance(sub_ref, dict) else sub_ref
                )
                if (
                    sub_ref_id == target_stripe_sub_id
                    and s.get("status") == "active"
                    and (s.get("metadata") or {}).get("source")
                    == "@better-auth/stripe"
                ):
                    await opts.stripe_client.release_subscription_schedule(s["id"])
                    if db_row:
                        await ctx.auth.adapter.update(
                            model="subscription",
                            where=(Where(field="id", value=db_row["id"]),),
                            update={
                                "stripeScheduleId": None,
                                "updatedAt": int(time.time()),
                            },
                        )
                    break

        # --- Multiset line-item diff (mirrors routes.ts 718-938) ------------
        # Resolve the active subscription's current base price, the new plan's
        # price + metered flag, and build a price-replacement map plus a
        # multiset delta of plan line items. These drive both the immediate
        # `subscriptions.update` and the scheduled-phase update so seat-price
        # swaps, add-ons, and removals are applied without duplicating items.
        sub_items_data = (existing_sub.get("items") or {}).get("data") or []
        resolved_plan_item = resolve_plan_item(opts, sub_items_data)
        planitem = resolved_plan_item.get("item") if resolved_plan_item else None
        stripe_subscription_price_id: str | None = None
        if planitem:
            _pp = planitem.get("price")
            stripe_subscription_price_id = (
                _pp.get("id") if isinstance(_pp, dict) else _pp
            )
        price_id_to_use = price_id  # new plan base price (line_items[0])

        resolved_new_price = await _resolve_price(
            opts,
            price_id=_plan_price_id(plan, annual=annual),
            lookup_key=_plan_lookup_key(plan, annual=annual),
        )
        is_metered = bool(plan.metered) or is_metered_price(resolved_new_price)
        is_auto_managed_seats = bool(
            plan.seat_price_id and customer_type == "organization"
        )
        old_plan = get_plan_by_name(opts, db_row["plan"]) if db_row else None

        # priceMap: oldPriceId -> {newPrice, quantity?} (seat-price changes).
        price_map: dict[str, dict[str, Any]] = {}
        if (
            is_auto_managed_seats
            and plan.seat_price_id
            and old_plan
            and old_plan.seat_price_id
            and old_plan.seat_price_id != plan.seat_price_id
        ):
            price_map[old_plan.seat_price_id] = {
                "newPrice": plan.seat_price_id,
                "quantity": member_count,
            }

        # lineItemDelta: old plan line items -1, new +1; drop zeros.
        line_item_delta: dict[str, int] = {}
        for li in old_plan.line_items if old_plan else []:
            lp = li.get("price")
            if isinstance(lp, str):
                line_item_delta[lp] = line_item_delta.get(lp, 0) - 1
        for li in plan.line_items:
            lp = li.get("price")
            if isinstance(lp, str):
                line_item_delta[lp] = line_item_delta.get(lp, 0) + 1
        for lp in list(line_item_delta):
            if line_item_delta[lp] == 0:
                del line_item_delta[lp]

        if body.scheduleAtPeriodEnd:
            # Deferred change: schedule the plan swap at the current billing
            # period end via Subscription Schedules. The active subscription is
            # left on its current plan; the webhook applies the change later.
            schedule = await opts.stripe_client.create_subscription_schedule(
                from_subscription=target_stripe_sub_id
            )
            phases = schedule.get("phases") or []
            if not phases:
                raise APIError(400, "Subscription schedule has no phases")
            current_phase = phases[0]

            def _price_of(item: dict[str, Any]) -> str | None:
                ip = item.get("price")
                return ip.get("id") if isinstance(ip, dict) else ip

            sched_remove_quota: dict[str, int] = {
                p: -d for p, d in line_item_delta.items() if d < 0
            }
            sched_delta = dict(line_item_delta)
            current_items = current_phase.get("items") or []
            new_phase_items: list[dict[str, Any]] = []
            for item in current_items:
                ip = _price_of(item)
                quota = sched_remove_quota.get(ip, 0)
                if quota > 0:
                    sched_remove_quota[ip] = quota - 1
                    continue
                replacement = price_map.get(ip)
                if replacement:
                    new_phase_items.append(
                        {
                            "price": replacement["newPrice"],
                            "quantity": replacement.get(
                                "quantity", item.get("quantity", 1)
                            ),
                        }
                    )
                    continue
                if ip == stripe_subscription_price_id:
                    entry: dict[str, Any] = {"price": price_id_to_use}
                    if not is_metered:
                        entry["quantity"] = (
                            1 if is_auto_managed_seats else (body.seats or 1)
                        )
                    new_phase_items.append(entry)
                    continue
                # Keep as-is; consume one positive delta to avoid re-adding it.
                new_phase_items.append(
                    {"price": ip, "quantity": item.get("quantity", 1)}
                )
                d = sched_delta.get(ip)
                if d is not None and d > 0:
                    if d == 1:
                        del sched_delta[ip]
                    else:
                        sched_delta[ip] = d - 1
            # Add line items the new plan introduces.
            for p, d in sched_delta.items():
                for _ in range(max(d, 0)):
                    new_phase_items.append({"price": p})

            await opts.stripe_client.update_subscription_schedule(
                schedule["id"],
                metadata={"source": "@better-auth/stripe"},
                end_behavior="release",
                phases=[
                    {
                        "items": [
                            {
                                "price": _price_of(item),
                                "quantity": item.get("quantity", 1),
                            }
                            for item in current_items
                        ],
                        "start_date": current_phase.get("start_date"),
                        "end_date": current_phase.get("end_date"),
                    },
                    {
                        "items": new_phase_items,
                        "start_date": current_phase.get("end_date"),
                        "proration_behavior": "none",
                    },
                ],
            )

            if db_row:
                await ctx.auth.adapter.update(
                    model="subscription",
                    where=(Where(field="id", value=db_row["id"]),),
                    update={
                        "stripeScheduleId": schedule["id"],
                        "updatedAt": int(time.time()),
                    },
                )
            return {"url": body.returnUrl or "/", "redirect": True}

        # Immediate change: build per-item updates via subscriptions.update.
        # Items the new plan removes are flagged `deleted`; seat/base/line-item
        # price changes are applied in place (preserving item ids); add-ons the
        # new plan introduces are appended; unchanged items are left untouched.
        immediate_remove_quota: dict[str, int] = {
            p: -d for p, d in line_item_delta.items() if d < 0
        }
        immediate_delta = dict(line_item_delta)
        update_items: list[dict[str, Any]] = []
        for si in sub_items_data:
            sp = si.get("price")
            si_price_id = sp.get("id") if isinstance(sp, dict) else sp
            si_id = si.get("id")
            quota = immediate_remove_quota.get(si_price_id, 0)
            if quota > 0:
                immediate_remove_quota[si_price_id] = quota - 1
                update_items.append({"id": si_id, "deleted": True})
                continue
            replacement = price_map.get(si_price_id)
            if replacement:
                update_items.append(
                    {
                        "id": si_id,
                        "price": replacement["newPrice"],
                        "quantity": replacement.get("quantity"),
                    }
                )
                continue
            if si_price_id == stripe_subscription_price_id:
                entry: dict[str, Any] = {"id": si_id, "price": price_id_to_use}
                if not is_metered:
                    entry["quantity"] = (
                        1 if is_auto_managed_seats else (body.seats or 1)
                    )
                update_items.append(entry)
                continue
            # Keep as-is; consume one positive delta to avoid re-adding it.
            d = immediate_delta.get(si_price_id)
            if d is not None and d > 0:
                if d == 1:
                    del immediate_delta[si_price_id]
                else:
                    immediate_delta[si_price_id] = d - 1
        # Add line items the new plan introduces.
        for p, d in immediate_delta.items():
            for _ in range(max(d, 0)):
                update_items.append({"price": p})

        updated = await opts.stripe_client.update_subscription(
            target_stripe_sub_id,
            items=update_items,
            proration_behavior=plan.proration_behavior,
            metadata={"referenceId": reference_id, "plan": plan.name},
        )

        now = int(time.time())
        await ctx.auth.adapter.update(
            model="subscription",
            where=(Where(field="stripeSubscriptionId", value=target_stripe_sub_id),),
            update={
                "plan": plan.name,
                "priceId": price_id,
                "billingInterval": billing_interval,
                "seats": member_count if is_auto_managed_seats else body.seats,
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


async def _upgrade_via_checkout(
    ctx: EndpointContext,
    opts: StripeOptions,
    *,
    plan: StripePlan,
    reference_id: str,
    customer_id: str,
    customer_type: str = "user",
    line_items: list[dict[str, Any]],
    billing_interval: str,
    body: UpgradeSubscriptionBody,
) -> dict[str, Any]:
    """Upgrade path when no active Stripe subscription exists.

    Mirrors upstream `routes.ts` (no `activeSubscription` branch): reuse an
    `incomplete` subscription row if present, otherwise create one, then open a
    Stripe Checkout session and return `{url, redirect}`.
    """
    seats = body.seats or 1
    # Reuse an existing incomplete row for this reference, else create one.
    existing = await ctx.auth.adapter.find_many(
        model="subscription",
        where=(Where(field="referenceId", value=reference_id),),
    )
    subscription = next(
        (s for s in existing if s.get("status") == "incomplete"), None
    )
    now = int(time.time())
    if subscription is None:
        subscription = await ctx.auth.adapter.create(
            model="subscription",
            data={
                "plan": plan.name.lower(),
                "stripeCustomerId": customer_id,
                "status": "incomplete",
                "referenceId": reference_id,
                "seats": seats,
                "cancelAtPeriodEnd": False,
                "createdAt": now,
                "updatedAt": now,
            },
        )
    else:
        await ctx.auth.adapter.update(
            model="subscription",
            where=(Where(field="id", value=subscription["id"]),),
            update={"plan": plan.name.lower(), "seats": seats, "updatedAt": now},
        )

    # Has this reference ever trialed? Prevents multiple trials by plan-hopping.
    has_ever_trialed = any(
        bool(s.get("trialStart") or s.get("trialEnd"))
        or s.get("status") == "trialing"
        for s in existing
    )

    # Optional caller hook returning `{params, options}` to customise the
    # Stripe Checkout session. Mirrors upstream `getCheckoutSessionParams`:
    # plugin-owned routing fields are stripped from the hook's params, the
    # remainder is spread *under* the library-owned fields, and a handful of
    # fields (customer_update, locale, subscription_data, metadata) follow
    # explicit precedence rules below.
    user_row = await _get_user_row(ctx)
    additional_params: dict[str, Any] = {}
    hook_options: Any = None
    if opts.get_checkout_session_params is not None:
        hook_result = await _maybe_await(
            opts.get_checkout_session_params(
                {
                    "user": user_row,
                    "session": ctx.session,
                    "plan": plan,
                    "subscription": subscription,
                },
                ctx.request,
                ctx,
            )
        )
        if hook_result:
            raw = dict(hook_result.get("params") or {})
            # Strip library-owned flow-routing fields so the hook can never
            # hijack them (mirrors upstream's destructure-and-discard).
            for owned in (
                "mode",
                "customer",
                "customer_email",
                "success_url",
                "cancel_url",
                "line_items",
                "client_reference_id",
            ):
                raw.pop(owned, None)
            additional_params = raw
            hook_options = hook_result.get("options")

    internal_metadata = {
        "userId": ctx.session.user_id,
        "subscriptionId": subscription["id"],
        "referenceId": reference_id,
    }

    sub_data: dict[str, Any] = {}
    if not has_ever_trialed and plan.free_trial:
        sub_data["trial_period_days"] = plan.free_trial.days
    elif not has_ever_trialed and plan.free_trial_days:
        sub_data["trial_period_days"] = plan.free_trial_days
    # Hook-supplied subscription_data is layered over the library trial, then
    # internal metadata is always re-applied on top so it can't be clobbered.
    hook_sub_data = dict(additional_params.get("subscription_data") or {})
    hook_sub_meta = hook_sub_data.pop("metadata", None)
    sub_data.update(hook_sub_data)
    sub_data["metadata"] = subscription_metadata.set(
        internal_metadata, body.metadata, hook_sub_meta
    )

    # customer_update default depends on customer type; the hook may override.
    default_customer_update = (
        {"name": "auto", "address": "auto"}
        if customer_type == "user"
        else {"address": "auto"}
    )

    params: dict[str, Any] = {
        **additional_params,
        "mode": "subscription",
        "customer": customer_id,
        "customer_update": additional_params.get("customer_update")
        or default_customer_update,
        "locale": body.locale or additional_params.get("locale"),
        "success_url": body.successUrl or body.returnUrl or "/",
        "cancel_url": body.cancelUrl or body.returnUrl or "/",
        "line_items": line_items,
        "client_reference_id": reference_id,
        "subscription_data": sub_data,
        "metadata": subscription_metadata.set(
            internal_metadata, body.metadata, additional_params.get("metadata")
        ),
    }
    if params.get("locale") is None:
        params.pop("locale")
    del hook_options  # request-level options (idempotency, etc.) — not in body
    session = await opts.stripe_client.create_checkout_session(**params)
    return {
        **session,
        "url": session.get("url"),
        "redirect": not body.disableRedirect,
    }


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
