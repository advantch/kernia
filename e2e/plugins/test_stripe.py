"""Stripe plugin end-to-end.

Drives the full lifecycle through the ASGI router using `MockStripe`:
  * `/stripe/checkout-session` calls Stripe → returns a Checkout URL.
  * The plugin's webhook handler verifies the signed event and persists the
    subscription row.
  * `/stripe/list-subscriptions` reflects the new row.
  * `/stripe/cancel-subscription` flips `cancelAtPeriodEnd`.
  * A bad signature is rejected with 400.
"""

from __future__ import annotations

import pytest

from kernia.auth import init
from kernia.plugins import email_and_password
from kernia.types.init_options import (
    KerniaOptions,
    EmailPasswordOptions,
    RateLimitOptions,
)
from kernia_memory_adapter import memory_adapter
from kernia_stripe import StripeClient, StripeOptions, StripePlan, stripe
from kernia_test_utils import ASGIDriver, MockStripe

WEBHOOK_SECRET = "whsec_test_secret"


def _sign_bytes(body: bytes, secret: str = WEBHOOK_SECRET) -> tuple[bytes, dict[str, str]]:
    """Sign exact bytes — the ASGI driver re-serializes via the stdlib defaults,
    so the test must sign that same serialization rather than the compact form
    used by `MockStripe.emit_webhook`.
    """
    import hashlib
    import hmac
    import time

    ts = int(time.time())
    signed = f"{ts}.".encode("ascii") + body
    sig = hmac.new(secret.encode("utf-8"), signed, hashlib.sha256).hexdigest()
    return body, {
        "stripe-signature": f"t={ts},v1={sig}",
        "content-type": "application/json",
    }


def _make_driver(
    *, create_customer_on_sign_up: bool = True
) -> tuple[ASGIDriver, MockStripe, object]:
    mock = MockStripe()
    client = StripeClient(api_key="sk_test_x", transport=mock.mock_transport())
    plugin = stripe(
        StripeOptions(
            stripe_client=client,
            webhook_secret=WEBHOOK_SECRET,
            create_customer_on_sign_up=create_customer_on_sign_up,
            plans={
                "pro": StripePlan(name="pro", price_id="price_pro"),
                "team": StripePlan(name="team", price_id="price_team", seats=True),
            },
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


async def _link_customer(auth: object, user_id: str, stripe_customer_id: str) -> None:
    """Link a Stripe customer id to a user row.

    Upstream's `customer.subscription.created` handler resolves the owning user
    (or org) via `stripeCustomerId`; a subscription created "from the Stripe
    dashboard" only persists locally once that link exists. Tests that drive the
    webhook directly must therefore seed the link first.
    """
    from better_auth.types.adapter import Where

    await auth.context.adapter.update(
        model="user",
        where=(Where(field="id", value=user_id),),
        update={"stripeCustomerId": stripe_customer_id},
    )


def _make_driver_with_auth() -> tuple[ASGIDriver, MockStripe, object]:
    mock = MockStripe()
    client = StripeClient(api_key="sk_test_x", transport=mock.mock_transport())
    plugin = stripe(
        StripeOptions(
            stripe_client=client,
            webhook_secret=WEBHOOK_SECRET,
            plans={"pro": StripePlan(name="pro", price_id="price_pro")},
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


async def _sign_up(driver: ASGIDriver, email: str = "sub@example.com") -> dict[str, object]:
    r = await driver.request(
        "POST",
        "/sign-up/email",
        json_body={"email": email, "password": "longstrongpw"},
    )
    assert r.status == 200, r.json()
    return r.json()


async def test_checkout_session_creates_stripe_customer_and_session() -> None:
    driver, mock, _auth = _make_driver()
    await _sign_up(driver)
    r = await driver.request(
        "POST",
        "/stripe/checkout-session",
        json_body={
            "plan": "pro",
            "successUrl": "https://app.test/success",
            "cancelUrl": "https://app.test/cancel",
        },
    )
    assert r.status == 200, r.json()
    body = r.json()
    assert body["url"].startswith("https://checkout.stripe.test/")
    assert body["id"].startswith("cs_")
    # MockStripe captured a customer-create call and a checkout-session-create.
    types = [e["type"] for e in mock.capture_events]
    assert "customer.create" in types
    assert "checkout.session.create" in types


async def test_webhook_signed_event_persists_subscription_and_list_reflects_it() -> None:
    driver, mock, auth = _make_driver()
    user = await _sign_up(driver)
    user_id = user["user"]["id"]

    # Pretend Stripe sent a customer.subscription.created event for a customer
    # that is already linked to this user (mirrors a subscription created from
    # the Stripe dashboard — the handler resolves the owner via stripeCustomerId).
    await _link_customer(auth, user_id, "cus_xxx")
    sub_id = "sub_test_001"
    event = {
        "id": "evt_001",
        "type": "customer.subscription.created",
        "data": {
            "object": {
                "id": sub_id,
                "customer": "cus_xxx",
                "status": "active",
                "cancel_at_period_end": False,
                "items": {
                    "data": [
                        {
                            "price": {"id": "price_pro"},
                            "current_period_start": 1700000000,
                            "current_period_end": 1700000000 + 30 * 86400,
                            "quantity": 1,
                        }
                    ]
                },
                "metadata": {"referenceId": user_id, "plan": "pro"},
            }
        },
    }
    # Sign the exact bytes the driver will send. The driver json.dumps the
    # body with default separators, so we compute the signature over that
    # same serialization rather than the compact one MockStripe.emit_webhook
    # uses.
    import json as _json

    body_bytes = _json.dumps(event).encode("utf-8")
    _, headers = _sign_bytes(body_bytes)
    r = await driver.request(
        "POST",
        "/stripe/webhook",
        json_body=event,
        headers=headers,
    )
    assert r.status == 200, r.json()
    assert r.json() == {"received": True}

    # list-subscriptions should now show the new row.
    r = await driver.request("GET", "/stripe/list-subscriptions")
    assert r.status == 200, r.json()
    subs = r.json()["subscriptions"]
    assert len(subs) == 1
    assert subs[0]["stripeSubscriptionId"] == sub_id
    assert subs[0]["status"] == "active"
    assert subs[0]["plan"] == "pro"


async def test_webhook_rejects_bad_signature() -> None:
    driver, _mock, _auth = _make_driver()
    await _sign_up(driver)
    event = {
        "id": "evt_bad",
        "type": "customer.subscription.created",
        "data": {"object": {"id": "sub_x", "metadata": {}}},
    }
    payload, _ = MockStripe.emit_webhook(event, "different-secret")
    import json as _json

    r = await driver.request(
        "POST",
        "/stripe/webhook",
        json_body=_json.loads(payload),
        headers={"stripe-signature": "t=1,v1=deadbeef"},
    )
    assert r.status == 400
    assert r.json()["code"] == "INVALID_SIGNATURE"


async def test_cancel_subscription_routes_through_billing_portal() -> None:
    """`/subscription/cancel` opens a Stripe billing-portal cancel flow.

    Mirrors upstream `subscription.test.ts`: cancellation is delegated to the
    billing portal (flow_data.type == "subscription_cancel") rather than mutating
    the row directly — the actual status change arrives later via webhook.
    """
    driver, mock, auth = _make_driver()
    user = await _sign_up(driver)
    user_id = user["user"]["id"]
    await _link_customer(auth, user_id, "cus_xxx")

    # Seed the live Stripe subscription the portal flow will target.
    sub_id = "sub_to_cancel"
    mock.subscriptions[sub_id] = {
        "id": sub_id,
        "object": "subscription",
        "customer": "cus_xxx",
        "status": "active",
        "cancel_at_period_end": False,
        "items": {"data": [{"price": {"id": "price_pro"}, "quantity": 1}]},
    }
    import json as _json

    event = {
        "id": "evt_seed",
        "type": "customer.subscription.created",
        "data": {
            "object": {
                "id": sub_id,
                "customer": "cus_xxx",
                "status": "active",
                "cancel_at_period_end": False,
                "items": {"data": [{"price": {"id": "price_pro"}, "quantity": 1}]},
                "metadata": {"referenceId": user_id, "plan": "pro"},
            }
        },
    }
    body_bytes = _json.dumps(event).encode("utf-8")
    _, headers = _sign_bytes(body_bytes)
    seed = await driver.request(
        "POST", "/stripe/webhook", json_body=event, headers=headers
    )
    assert seed.status == 200, seed.json()

    r = await driver.request(
        "POST",
        "/subscription/cancel",
        json_body={"subscriptionId": sub_id, "returnUrl": "/account"},
    )
    assert r.status == 200, r.json()
    body = r.json()
    assert body["url"].startswith("https://billing.stripe.test/")
    assert body["redirect"] is True

    # The portal session must carry a subscription_cancel flow for this sub.
    portal_event = next(
        e for e in mock.capture_events if e["type"] == "billing_portal.session.create"
    )
    flow = portal_event["object"]["flow_data"]
    assert flow["type"] == "subscription_cancel"
    assert flow["subscription_cancel"]["subscription"] == sub_id


async def test_missing_signature_header_returns_400() -> None:
    driver, _mock, _auth = _make_driver()
    await _sign_up(driver)
    r = await driver.request(
        "POST",
        "/stripe/webhook",
        json_body={"id": "evt", "type": "noop"},
    )
    assert r.status == 400
    assert r.json()["code"] == "INVALID_SIGNATURE"


async def test_catalog_sync_imports_products_and_prices() -> None:
    driver, mock = _make_driver()
    await _sign_up(driver)

    r = await driver.request("POST", "/stripe/catalog/sync")
    assert r.status == 200, r.json()
    assert r.json() == {"products": 1, "prices": 1}

    r = await driver.request("GET", "/stripe/products")
    assert r.status == 200
    assert r.json()["products"][0]["stripeProductId"] == "prod_starter"

    r = await driver.request("GET", "/stripe/prices")
    assert r.status == 200
    assert r.json()["prices"][0]["stripePriceId"] == "price_starter_monthly"


async def test_billing_check_track_and_usage() -> None:
    driver, _mock, auth = _make_driver_with_auth()
    user = await _sign_up(driver, email="usage@example.com")
    user_id = user["user"]["id"]
    await auth.context.adapter.create(
        model="billingEntitlement",
        data={
            "referenceId": user_id,
            "featureKey": "projects",
            "included": 2,
            "used": 0,
            "unlimited": False,
            "overageAllowed": False,
            "createdAt": 1,
            "updatedAt": 1,
        },
    )

    r = await driver.request(
        "POST",
        "/billing/check",
        json_body={"feature": "projects", "required": 1},
    )
    assert r.status == 200
    assert r.json()["allowed"] is True
    assert r.json()["remaining"] == 2

    r = await driver.request(
        "POST",
        "/billing/track",
        json_body={"feature": "projects", "quantity": 2, "properties": {"source": "test"}},
    )
    assert r.status == 200
    assert r.json()["entitlement"]["remaining"] == 0

    r = await driver.request(
        "POST",
        "/billing/check",
        json_body={"feature": "projects", "required": 1},
    )
    assert r.status == 200
    assert r.json()["allowed"] is False

    r = await driver.request("GET", "/billing/usage")
    assert r.status == 200
    assert r.json()["usage"][0]["featureKey"] == "projects"


async def test_billing_customer_and_portal_alias() -> None:
    driver, _mock = _make_driver()
    await _sign_up(driver, email="portal@example.com")

    r = await driver.request("GET", "/billing/customer")
    assert r.status == 200
    assert r.json()["customer"]["stripeCustomerId"].startswith("cus_")

    r = await driver.request("GET", "/billing/portal")
    assert r.status == 200
    assert r.json()["url"].startswith("https://billing.stripe.test/")
