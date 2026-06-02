"""Trial-abuse prevention + trial-data propagation from Stripe events.

Ports the `describe("trial abuse prevention")` block of
`reference/packages/stripe/test/subscription.test.ts`:

  * A free trial is granted at checkout only when the reference has *no* trial
    history on *any* of its subscriptions — even when the upgrade targets a
    specific (incomplete) subscription id.
  * `customer.subscription.deleted` / `customer.subscription.updated` webhooks
    propagate `trial_start` / `trial_end` from the Stripe event onto the local
    subscription row (so a missed checkout webhook can't reset trial history).
  * After a subscription that trialed is canceled, re-subscribing must not grant
    another trial.

Contract note: the Python port stores `trialStart`/`trialEnd` as epoch seconds
(consistent with `periodStart`/`periodEnd`), so assertions compare against the
raw second values rather than upstream's `Date.getTime()` milliseconds.
"""

from __future__ import annotations

import hashlib
import hmac
import json as _json
import time
from typing import Any

from kernia.auth import init
from kernia.plugins.email_password import email_and_password
from kernia.types.adapter import Where
from kernia.types.init_options import (
    KerniaOptions,
    EmailPasswordOptions,
    RateLimitOptions,
)
from kernia_memory_adapter import memory_adapter
from kernia_stripe import StripeClient, StripeOptions, StripePlan, stripe
from kernia_stripe.schema import FreeTrial
from kernia_test_utils import ASGIDriver, MockStripe

WEBHOOK_SECRET = "whsec_test_secret"


def _trial_plans() -> dict[str, StripePlan]:
    return {
        "starter": StripePlan(
            name="starter", price_id="price_starter", free_trial=FreeTrial(days=7)
        ),
        "premium": StripePlan(
            name="premium", price_id="price_premium", free_trial=FreeTrial(days=7)
        ),
    }


def _build() -> tuple[ASGIDriver, MockStripe, object]:
    mock = MockStripe()
    mock.add_price("price_starter", usage_type="licensed")
    mock.add_price("price_premium", usage_type="licensed")
    client = StripeClient(api_key="sk_test_x", transport=mock.mock_transport())
    plugin = stripe(
        StripeOptions(
            stripe_client=client,
            webhook_secret=WEBHOOK_SECRET,
            create_customer_on_sign_up=False,
            plans=_trial_plans(),
        )
    )
    auth = init(
        KerniaOptions(
            database=memory_adapter(),
            secret="stripe-secret",
            email_and_password=EmailPasswordOptions(enabled=True),
            plugins=[email_and_password(), plugin],
            rate_limit=RateLimitOptions(enabled=False),
        )
    )
    return ASGIDriver(app=auth.router.mount()), mock, auth


async def _signup(driver: ASGIDriver, email: str) -> str:
    r = await driver.request(
        "POST",
        "/sign-up/email",
        json_body={"email": email, "password": "longstrongpw", "name": email},
    )
    assert r.status == 200, r.json()
    return r.json()["user"]["id"]


def _sign(body: bytes) -> dict[str, str]:
    ts = int(time.time())
    sig = hmac.new(
        WEBHOOK_SECRET.encode("utf-8"),
        f"{ts}.".encode("ascii") + body,
        hashlib.sha256,
    ).hexdigest()
    return {
        "stripe-signature": f"t={ts},v1={sig}",
        "content-type": "application/json",
    }


async def _post_webhook(driver: ASGIDriver, event: dict[str, Any]) -> Any:
    body_bytes = _json.dumps(event).encode("utf-8")
    return await driver.request(
        "POST", "/stripe/webhook", json_body=event, headers=_sign(body_bytes)
    )


def _last_checkout_params(mock: MockStripe) -> dict[str, Any]:
    evs = [e for e in mock.capture_events if e["type"] == "checkout.session.create"]
    assert evs, "expected a checkout session to be created"
    return evs[-1]["params"]


def _has_trial(params: dict[str, Any]) -> bool:
    return any(k.startswith("subscription_data[trial_period_days") for k in params)


# ---------------------------------------------------------------------------
# trial history is checked across ALL subscriptions
# ---------------------------------------------------------------------------


async def test_checks_all_subscriptions_for_trial_history() -> None:
    driver, mock, auth = _build()
    user_id = await _signup(driver, "trial-findone@email.com")
    adapter = auth.context.adapter  # type: ignore[attr-defined]

    now = int(time.time())
    # A canceled subscription that already used a trial.
    await adapter.create(
        model="subscription",
        data={
            "referenceId": user_id,
            "stripeCustomerId": "cus_old_customer",
            "status": "canceled",
            "plan": "starter",
            "stripeSubscriptionId": "sub_canceled_with_trial",
            "trialStart": now - 1000,
            "trialEnd": now - 500,
        },
    )
    # A new incomplete subscription with no trial info.
    await adapter.create(
        model="subscription",
        data={
            "referenceId": user_id,
            "stripeCustomerId": "cus_old_customer",
            "status": "incomplete",
            "plan": "premium",
            "stripeSubscriptionId": "sub_incomplete_new",
        },
    )

    # Upgrading against the *incomplete* sub must still scan all subs for trial
    # history → no trial granted.
    r = await driver.request(
        "POST",
        "/subscription/upgrade",
        json_body={"plan": "premium", "subscriptionId": "sub_incomplete_new"},
    )
    assert r.status == 200, r.json()
    assert r.json()["url"] is not None
    assert not _has_trial(_last_checkout_params(mock))


# ---------------------------------------------------------------------------
# trial data propagation from Stripe events
# ---------------------------------------------------------------------------


async def test_propagates_trial_data_on_subscription_deleted() -> None:
    driver, _mock, auth = _build()
    adapter = auth.context.adapter  # type: ignore[attr-defined]
    user = await adapter.create(model="user", data={"email": "trial-del@test.com"})

    now = int(time.time())
    trial_start = now - 3 * 86400
    trial_end = now + 4 * 86400
    sub = await adapter.create(
        model="subscription",
        data={
            "referenceId": user["id"],
            "stripeCustomerId": "cus_trial_deleted_propagate",
            "stripeSubscriptionId": "sub_trial_deleted_propagate",
            "status": "trialing",
            "plan": "starter",
        },
    )

    event = {
        "id": "evt_del",
        "type": "customer.subscription.deleted",
        "data": {
            "object": {
                "id": "sub_trial_deleted_propagate",
                "customer": "cus_trial_deleted_propagate",
                "status": "canceled",
                "trial_start": trial_start,
                "trial_end": trial_end,
                "canceled_at": now,
                "ended_at": now,
            }
        },
    }
    r = await _post_webhook(driver, event)
    assert r.status == 200, r.json()

    updated = await adapter.find_one(
        model="subscription", where=(Where(field="id", value=sub["id"]),)
    )
    assert updated["status"] == "canceled"
    assert updated["trialStart"] == trial_start
    assert updated["trialEnd"] == trial_end


async def test_propagates_trial_data_on_subscription_updated() -> None:
    driver, _mock, auth = _build()
    adapter = auth.context.adapter  # type: ignore[attr-defined]
    user = await adapter.create(model="user", data={"email": "trial-upd@test.com"})

    now = int(time.time())
    trial_start = now - 7 * 86400
    trial_end = now
    period_end = now + 30 * 86400
    sub = await adapter.create(
        model="subscription",
        data={
            "referenceId": user["id"],
            "stripeCustomerId": "cus_trial_updated_propagate",
            "stripeSubscriptionId": "sub_trial_updated_propagate",
            "status": "trialing",
            "plan": "starter",
        },
    )

    event = {
        "id": "evt_upd",
        "type": "customer.subscription.updated",
        "data": {
            "object": {
                "id": "sub_trial_updated_propagate",
                "customer": "cus_trial_updated_propagate",
                "status": "active",
                "cancel_at_period_end": False,
                "trial_start": trial_start,
                "trial_end": trial_end,
                "metadata": {"subscriptionId": sub["id"]},
                "items": {
                    "data": [
                        {
                            "id": "si_test_item",
                            "price": {"id": "price_starter"},
                            "quantity": 1,
                            "current_period_start": now,
                            "current_period_end": period_end,
                        }
                    ]
                },
            }
        },
    }
    r = await _post_webhook(driver, event)
    assert r.status == 200, r.json()

    updated = await adapter.find_one(
        model="subscription", where=(Where(field="id", value=sub["id"]),)
    )
    assert updated["status"] == "active"
    assert updated["trialStart"] == trial_start
    assert updated["trialEnd"] == trial_end


# ---------------------------------------------------------------------------
# no second trial after a trialed subscription is canceled
# ---------------------------------------------------------------------------


async def test_prevents_trial_abuse_after_cancel_during_trial() -> None:
    driver, mock, auth = _build()
    user_id = await _signup(driver, "trial-abuse-cancel@email.com")
    adapter = auth.context.adapter  # type: ignore[attr-defined]

    now = int(time.time())
    trial_start = now - 3 * 86400
    trial_end = now + 4 * 86400
    # Canceled sub recorded without trial data (missed checkout webhook).
    await adapter.create(
        model="subscription",
        data={
            "referenceId": user_id,
            "stripeCustomerId": "cus_trial_abuse",
            "stripeSubscriptionId": "sub_trial_abuse_old",
            "status": "canceled",
            "plan": "starter",
        },
    )

    # The deletion webhook backfills the trial dates from Stripe.
    event = {
        "id": "evt_abuse",
        "type": "customer.subscription.deleted",
        "data": {
            "object": {
                "id": "sub_trial_abuse_old",
                "customer": "cus_trial_abuse",
                "status": "canceled",
                "trial_start": trial_start,
                "trial_end": trial_end,
                "canceled_at": now,
                "ended_at": now,
            }
        },
    }
    assert (await _post_webhook(driver, event)).status == 200

    # Re-subscribing must not grant a second trial.
    r = await driver.request(
        "POST", "/subscription/upgrade", json_body={"plan": "starter"}
    )
    assert r.status == 200, r.json()
    assert r.json()["url"] is not None
    assert not _has_trial(_last_checkout_params(mock))
