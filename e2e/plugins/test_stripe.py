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

from better_auth.auth import init
from better_auth.plugins import email_and_password
from better_auth.types.init_options import (
    BetterAuthOptions,
    EmailPasswordOptions,
    RateLimitOptions,
)
from better_auth_memory_adapter import memory_adapter
from better_auth_stripe import StripeClient, StripeOptions, StripePlan, stripe
from better_auth_test_utils import ASGIDriver, MockStripe


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


def _make_driver() -> tuple[ASGIDriver, MockStripe]:
    mock = MockStripe()
    client = StripeClient(api_key="sk_test_x", transport=mock.mock_transport())
    plugin = stripe(
        StripeOptions(
            stripe_client=client,
            webhook_secret=WEBHOOK_SECRET,
            plans={
                "pro": StripePlan(name="pro", price_id="price_pro"),
                "team": StripePlan(name="team", price_id="price_team", seats=True),
            },
        )
    )
    auth = init(
        BetterAuthOptions(
            database=memory_adapter(),
            secret="stripe-secret",
            email_and_password=EmailPasswordOptions(enabled=True),
            plugins=[email_and_password(), plugin],
            rate_limit=RateLimitOptions(enabled=False),
        )
    )
    return ASGIDriver(app=auth.router.mount()), mock


async def _sign_up(driver: ASGIDriver, email: str = "sub@example.com") -> dict[str, object]:
    r = await driver.request(
        "POST",
        "/sign-up/email",
        json_body={"email": email, "password": "longstrongpw"},
    )
    assert r.status == 200, r.json()
    return r.json()


async def test_checkout_session_creates_stripe_customer_and_session() -> None:
    driver, mock = _make_driver()
    user = await _sign_up(driver)
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
    driver, mock = _make_driver()
    user = await _sign_up(driver)
    user_id = user["user"]["id"]

    # Pretend Stripe sent a customer.subscription.created event referencing
    # the same user via the metadata payload.
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
    driver, _mock = _make_driver()
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


async def test_cancel_subscription_updates_status_and_flag() -> None:
    driver, mock = _make_driver()
    user = await _sign_up(driver)
    user_id = user["user"]["id"]

    # Seed a subscription row + a Stripe subscription object directly.
    sub_id = "sub_to_cancel"
    mock.subscriptions[sub_id] = {
        "id": sub_id,
        "object": "subscription",
        "customer": "cus_xxx",
        "status": "active",
        "cancel_at_period_end": False,
    }
    # Insert the matching subscription row via the webhook flow so the DB has it.
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
                "items": {"data": []},
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
        "/stripe/cancel-subscription",
        json_body={"subscriptionId": sub_id, "cancelAtPeriodEnd": True},
    )
    assert r.status == 200, r.json()
    # Underlying mock state was updated by the plugin.
    assert mock.subscriptions[sub_id]["cancel_at_period_end"] is True

    # And the row reflects the new flag.
    r = await driver.request("GET", "/stripe/list-subscriptions")
    subs = r.json()["subscriptions"]
    assert subs[0]["cancelAtPeriodEnd"] is True


async def test_missing_signature_header_returns_400() -> None:
    driver, _ = _make_driver()
    await _sign_up(driver)
    r = await driver.request(
        "POST",
        "/stripe/webhook",
        json_body={"id": "evt", "type": "noop"},
    )
    assert r.status == 400
    assert r.json()["code"] == "INVALID_SIGNATURE"


# ----- metered / usage-based billing parity --------------------------------


def _make_metered_driver() -> tuple[ASGIDriver, MockStripe]:
    """Driver with a metered plan (usage-based) and a licensed plan."""
    mock = MockStripe()
    # Register a metered price so resolve→isMeteredPrice returns True.
    mock.add_price("price_metered", usage_type="metered")
    mock.add_price("price_pro", usage_type="licensed")
    mock.add_price("price_pro_annual", usage_type="licensed", interval="year")
    client = StripeClient(api_key="sk_test_x", transport=mock.mock_transport())
    plugin = stripe(
        StripeOptions(
            stripe_client=client,
            webhook_secret=WEBHOOK_SECRET,
            plans={
                "metered": StripePlan(name="metered", price_id="price_metered"),
                "pro": StripePlan(
                    name="pro",
                    price_id="price_pro",
                    annual_price_id="price_pro_annual",
                ),
            },
        )
    )
    auth = init(
        BetterAuthOptions(
            database=memory_adapter(),
            secret="stripe-secret",
            email_and_password=EmailPasswordOptions(enabled=True),
            plugins=[email_and_password(), plugin],
            rate_limit=RateLimitOptions(enabled=False),
        )
    )
    return ASGIDriver(app=auth.router.mount()), mock


async def test_metered_checkout_omits_quantity_on_line_item() -> None:
    driver, mock = _make_metered_driver()
    await _sign_up(driver, email="metered@example.com")
    r = await driver.request(
        "POST",
        "/stripe/checkout-session",
        json_body={
            "plan": "metered",
            "successUrl": "https://app.test/success",
            "cancelUrl": "https://app.test/cancel",
            "seats": 5,
        },
    )
    assert r.status == 200, r.json()
    # The captured checkout session must carry a line item with NO quantity for
    # the metered price (Stripe rejects quantity on metered items).
    session_event = next(
        e for e in mock.capture_events if e["type"] == "checkout.session.create"
    )
    line_items = session_event["object"]["line_items"]
    assert len(line_items) == 1
    assert line_items[0]["price"] == "price_metered"
    assert "quantity" not in line_items[0]


async def test_licensed_checkout_includes_quantity() -> None:
    driver, mock = _make_metered_driver()
    await _sign_up(driver, email="licensed@example.com")
    r = await driver.request(
        "POST",
        "/stripe/checkout-session",
        json_body={
            "plan": "pro",
            "successUrl": "https://app.test/success",
            "cancelUrl": "https://app.test/cancel",
            "seats": 3,
        },
    )
    assert r.status == 200, r.json()
    session_event = next(
        e for e in mock.capture_events if e["type"] == "checkout.session.create"
    )
    line_items = session_event["object"]["line_items"]
    assert line_items[0]["price"] == "price_pro"
    assert line_items[0]["quantity"] == "3"


async def test_upgrade_subscription_swaps_price_with_proration() -> None:
    driver, mock = _make_metered_driver()
    user = await _sign_up(driver, email="upgrade@example.com")
    user_id = user["user"]["id"]

    # Seed an existing licensed subscription via the webhook flow.
    sub_id = "sub_upgrade_001"
    mock.subscriptions[sub_id] = {
        "id": sub_id,
        "object": "subscription",
        "customer": "cus_up",
        "status": "active",
        "cancel_at_period_end": False,
        "items": {"data": [{"id": "si_existing", "price": {"id": "price_pro"}, "quantity": 1}]},
    }
    import json as _json

    event = {
        "id": "evt_up_seed",
        "type": "customer.subscription.created",
        "data": {
            "object": {
                "id": sub_id,
                "customer": "cus_up",
                "status": "active",
                "cancel_at_period_end": False,
                "items": {"data": [{"quantity": 1}]},
                "metadata": {"referenceId": user_id, "plan": "pro"},
            }
        },
    }
    body_bytes = _json.dumps(event).encode("utf-8")
    _, headers = _sign_bytes(body_bytes)
    seed = await driver.request("POST", "/stripe/webhook", json_body=event, headers=headers)
    assert seed.status == 200, seed.json()

    # Upgrade pro → metered: the new line item must omit quantity and the
    # update must carry the plan's proration behavior.
    r = await driver.request(
        "POST",
        "/subscription/upgrade",
        json_body={"plan": "metered", "subscriptionId": sub_id},
    )
    assert r.status == 200, r.json()
    payload = r.json()
    assert payload["plan"] == "metered"

    # Stripe-side: the item price was swapped (id reused) and metered → no qty.
    items = mock.subscriptions[sub_id]["items"]["data"]
    assert items[0]["price"]["id"] == "price_metered"
    assert items[0]["id"] == "si_existing"
    assert "quantity" not in items[0]
    update_event = next(
        e for e in mock.capture_events if e["type"] == "subscription.update"
    )
    assert update_event["object"]["proration_behavior"] == "create_prorations"

    # DB row reflects the new plan + price id.
    r = await driver.request("GET", "/stripe/list-subscriptions")
    row = r.json()["subscriptions"][0]
    assert row["plan"] == "metered"
    assert row["priceId"] == "price_metered"
    assert row["billingInterval"] == "month"
