"""Ported from reference/packages/stripe/test/webhook.test.ts.

Covers webhook-driven subscription creation edge cases. Upstream mocks the
Stripe client's `webhooks.constructEventAsync`; this port signs the exact bytes
the ASGI driver sends and POSTs them to `/stripe/webhook`, asserting the same
DB-side effects (billingInterval stored, early-return when no plan / when a
metadata.subscriptionId already points at a row).

The broader webhook lifecycle (deletion, no-dupe, no-reference, update/cancel
callbacks, schedule sync, trial-end) is covered in `e2e/plugins/test_stripe.py`
under the same upstream case names.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import Any

from better_auth.auth import init
from better_auth.plugins import email_and_password
from better_auth.types.adapter import Where
from better_auth.types.init_options import (
    BetterAuthOptions,
    EmailPasswordOptions,
    RateLimitOptions,
)
from better_auth_memory_adapter import memory_adapter
from better_auth_stripe import StripeClient, StripeOptions, StripePlan, stripe
from better_auth_test_utils import ASGIDriver, MockStripe

WEBHOOK_SECRET = "test_secret"


def _make(**opts_overrides: Any) -> tuple[ASGIDriver, MockStripe, Any]:
    mock = MockStripe()
    client = StripeClient(api_key="sk_test", transport=mock.mock_transport())
    opts = StripeOptions(
        stripe_client=client,
        webhook_secret=WEBHOOK_SECRET,
        plans={
            "starter": StripePlan(name="starter", price_id="price_test_1"),
            "premium": StripePlan(name="premium", price_id="price_test_2"),
        },
        **opts_overrides,
    )
    auth = init(
        BetterAuthOptions(
            database=memory_adapter(),
            secret="stripe-secret",
            email_and_password=EmailPasswordOptions(enabled=True),
            plugins=[email_and_password(), stripe(opts)],
            rate_limit=RateLimitOptions(enabled=False),
        )
    )
    return ASGIDriver(app=auth.router.mount()), mock, auth


def _signed(event: dict[str, Any]) -> tuple[dict[str, Any], dict[str, str]]:
    body = json.dumps(event).encode("utf-8")
    ts = int(time.time())
    sig = hmac.new(
        WEBHOOK_SECRET.encode(), f"{ts}.".encode("ascii") + body, hashlib.sha256
    ).hexdigest()
    return event, {
        "stripe-signature": f"t={ts},v1={sig}",
        "content-type": "application/json",
    }


async def _create_user(auth: Any, *, email: str, customer_id: str) -> str:
    now = int(time.time())
    row = await auth.context.adapter.create(
        model="user",
        data={
            "email": email,
            "name": "Test",
            "emailVerified": True,
            "stripeCustomerId": customer_id,
            "createdAt": now,
            "updatedAt": now,
        },
    )
    return row["id"]


async def test_stores_billing_interval_year_for_annual_subscriptions() -> None:
    driver, _mock, auth = _make()
    uid = await _create_user(
        auth, email="annual-user@test.com", customer_id="cus_annual_test"
    )
    now = int(time.time())
    event, headers = _signed(
        {
            "id": "evt_annual",
            "type": "customer.subscription.created",
            "data": {
                "object": {
                    "id": "sub_annual_created",
                    "customer": "cus_annual_test",
                    "status": "active",
                    "cancel_at_period_end": False,
                    "items": {
                        "data": [
                            {
                                "price": {
                                    "id": "price_test_1",
                                    "recurring": {"interval": "year"},
                                },
                                "quantity": 1,
                                "current_period_start": now,
                                "current_period_end": now + 365 * 86400,
                            }
                        ]
                    },
                }
            },
        }
    )
    r = await driver.request(
        "POST", "/stripe/webhook", json_body=event, headers=headers
    )
    assert r.status == 200, r.json()

    sub = await auth.context.adapter.find_one(
        model="subscription",
        where=(Where(field="stripeSubscriptionId", value="sub_annual_created"),),
    )
    assert sub is not None
    assert sub["referenceId"] == uid
    assert sub["billingInterval"] == "year"


async def test_skips_subscription_creation_when_plan_not_found() -> None:
    called: dict[str, Any] = {}

    async def on_created(_data: dict[str, Any]) -> None:
        called["hit"] = True

    driver, _mock, auth = _make(on_subscription_created=on_created)
    await _create_user(auth, email="no-plan@test.com", customer_id="cus_no_plan")
    now = int(time.time())
    event, headers = _signed(
        {
            "id": "evt_no_plan",
            "type": "customer.subscription.created",
            "data": {
                "object": {
                    "id": "sub_no_plan",
                    "customer": "cus_no_plan",
                    "status": "active",
                    "cancel_at_period_end": False,
                    "items": {
                        "data": [
                            {
                                "price": {"id": "price_unknown"},
                                "quantity": 1,
                                "current_period_start": now,
                                "current_period_end": now + 30 * 86400,
                            }
                        ]
                    },
                }
            },
        }
    )
    r = await driver.request(
        "POST", "/stripe/webhook", json_body=event, headers=headers
    )
    assert r.status == 200, r.json()

    sub = await auth.context.adapter.find_one(
        model="subscription",
        where=(Where(field="stripeSubscriptionId", value="sub_no_plan"),),
    )
    assert sub is None
    assert "hit" not in called


async def test_skips_creation_when_metadata_subscription_id_exists() -> None:
    driver, _mock, auth = _make()
    uid = await _create_user(
        auth, email="meta-sub@test.com", customer_id="cus_meta_sub"
    )
    # Seed an existing incomplete row; the event's metadata.subscriptionId points
    # at it, so the created handler must NOT insert a second row.
    now = int(time.time())
    existing = await auth.context.adapter.create(
        model="subscription",
        data={
            "plan": "starter",
            "referenceId": uid,
            "status": "incomplete",
            "stripeCustomerId": "cus_meta_sub",
            "createdAt": now,
            "updatedAt": now,
        },
    )
    event, headers = _signed(
        {
            "id": "evt_meta_sub",
            "type": "customer.subscription.created",
            "data": {
                "object": {
                    "id": "sub_meta_new",
                    "customer": "cus_meta_sub",
                    "status": "active",
                    "cancel_at_period_end": False,
                    "items": {
                        "data": [
                            {
                                "price": {"id": "price_test_1"},
                                "quantity": 1,
                                "current_period_start": now,
                                "current_period_end": now + 30 * 86400,
                            }
                        ]
                    },
                    "metadata": {
                        "subscriptionId": existing["id"],
                        "referenceId": uid,
                    },
                }
            },
        }
    )
    r = await driver.request(
        "POST", "/stripe/webhook", json_body=event, headers=headers
    )
    assert r.status == 200, r.json()

    rows = await auth.context.adapter.find_many(
        model="subscription", where=(Where(field="referenceId", value=uid),)
    )
    assert len(list(rows)) == 1
