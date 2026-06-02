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
    from kernia.types.adapter import Where

    await auth.context.adapter.update(
        model="user",
        where=(Where(field="id", value=user_id),),
        update={"stripeCustomerId": stripe_customer_id},
    )


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


# ----- metered / usage-based billing parity --------------------------------


def _make_metered_driver() -> tuple[ASGIDriver, MockStripe, object]:
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
        KerniaOptions(
            database=memory_adapter(),
            secret="stripe-secret",
            email_and_password=EmailPasswordOptions(enabled=True),
            plugins=[email_and_password(), plugin],
            rate_limit=RateLimitOptions(enabled=False),
        )
    )
    return ASGIDriver(app=auth.router.mount()), mock, auth


async def test_metered_checkout_omits_quantity_on_line_item() -> None:
    driver, mock, _auth = _make_metered_driver()
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
    driver, mock, _auth = _make_metered_driver()
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
    driver, mock, auth = _make_metered_driver()
    user = await _sign_up(driver, email="upgrade@example.com")
    user_id = user["user"]["id"]
    await _link_customer(auth, user_id, "cus_up")

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
                "items": {"data": [{"price": {"id": "price_pro"}, "quantity": 1}]},
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


# ----- webhook lifecycle parity --------------------------------------------
#
# These mirror upstream `webhook.test.ts`, adapted to this harness: instead of
# mocking the Stripe client's `webhooks.constructEventAsync`, we sign the exact
# bytes and POST them. The behavioral assertions (which DB columns change, which
# lifecycle callbacks fire and with what payload) are kept 1:1 with upstream.


def _signed(event: dict[str, object]) -> tuple[dict[str, object], dict[str, str]]:
    import json as _json

    body_bytes = _json.dumps(event).encode("utf-8")
    _, headers = _sign_bytes(body_bytes)
    return event, headers


async def _seed_db_subscription(
    auth: object, *, reference_id: str, customer_id: str, sub_id: str, **extra: object
) -> dict[str, object]:
    """Insert a subscription row directly (mirrors upstream `adapter.create`)."""
    import time as _time

    from kernia.types.adapter import Where

    now = int(_time.time())
    data = {
        "referenceId": reference_id,
        "stripeCustomerId": customer_id,
        "stripeSubscriptionId": sub_id,
        "status": "active",
        "plan": "pro",
        "createdAt": now,
        "updatedAt": now,
        **extra,
    }
    await auth.context.adapter.create(model="subscription", data=data)
    return await auth.context.adapter.find_one(
        model="subscription",
        where=(Where(field="stripeSubscriptionId", value=sub_id),),
    )


async def test_subscription_deleted_webhook_marks_canceled() -> None:
    """customer.subscription.deleted flips the row to status=canceled."""
    driver, mock, auth = _make_driver()
    user = await _sign_up(driver, email="delete-test@email.com")
    user_id = user["user"]["id"]
    await _link_customer(auth, user_id, "cus_delete")
    await _seed_db_subscription(
        auth, reference_id=user_id, customer_id="cus_delete", sub_id="sub_delete"
    )

    event, headers = _signed(
        {
            "id": "evt_del",
            "type": "customer.subscription.deleted",
            "data": {
                "object": {
                    "id": "sub_delete",
                    "customer": "cus_delete",
                    "status": "canceled",
                    "ended_at": 1700000000,
                }
            },
        }
    )
    r = await driver.request(
        "POST", "/stripe/webhook", json_body=event, headers=headers
    )
    assert r.status == 200, r.json()

    from kernia.types.adapter import Where

    row = await auth.context.adapter.find_one(
        model="subscription",
        where=(Where(field="stripeSubscriptionId", value="sub_delete"),),
    )
    assert row["status"] == "canceled"
    assert row["endedAt"] == 1700000000


async def test_subscription_created_webhook_does_not_duplicate() -> None:
    """A second created event for an existing row must not insert a duplicate."""
    driver, mock, auth = _make_driver()
    user = await _sign_up(driver, email="nodupe@email.com")
    user_id = user["user"]["id"]
    await _link_customer(auth, user_id, "cus_nodupe")
    await _seed_db_subscription(
        auth, reference_id=user_id, customer_id="cus_nodupe", sub_id="sub_nodupe"
    )

    event, headers = _signed(
        {
            "id": "evt_nodupe",
            "type": "customer.subscription.created",
            "data": {
                "object": {
                    "id": "sub_nodupe",
                    "customer": "cus_nodupe",
                    "status": "active",
                    "items": {"data": [{"price": {"id": "price_pro"}, "quantity": 1}]},
                    "metadata": {},
                }
            },
        }
    )
    r = await driver.request(
        "POST", "/stripe/webhook", json_body=event, headers=headers
    )
    assert r.status == 200, r.json()

    from kernia.types.adapter import Where

    rows = await auth.context.adapter.find_many(
        model="subscription",
        where=(Where(field="referenceId", value=user_id),),
    )
    assert len(list(rows)) == 1


async def test_subscription_created_webhook_skips_when_no_reference() -> None:
    """No user/org linked to the customer → no row is created."""
    driver, mock, auth = _make_driver()
    user = await _sign_up(driver, email="noref@email.com")
    user_id = user["user"]["id"]
    # Deliberately do NOT link cus_orphan to any user.

    event, headers = _signed(
        {
            "id": "evt_noref",
            "type": "customer.subscription.created",
            "data": {
                "object": {
                    "id": "sub_orphan",
                    "customer": "cus_orphan",
                    "status": "active",
                    "items": {"data": [{"price": {"id": "price_pro"}, "quantity": 1}]},
                    "metadata": {},
                }
            },
        }
    )
    r = await driver.request(
        "POST", "/stripe/webhook", json_body=event, headers=headers
    )
    assert r.status == 200, r.json()

    from kernia.types.adapter import Where

    rows = await auth.context.adapter.find_many(
        model="subscription",
        where=(Where(field="referenceId", value=user_id),),
    )
    assert list(rows) == []


async def test_subscription_updated_webhook_invokes_callbacks() -> None:
    """onSubscriptionUpdate fires with the post-update row + the Stripe object."""
    captured: dict[str, object] = {}

    mock = MockStripe()
    client = StripeClient(api_key="sk_test_x", transport=mock.mock_transport())

    async def on_update(data: dict[str, object]) -> None:
        captured["update"] = data

    plugin = stripe(
        StripeOptions(
            stripe_client=client,
            webhook_secret=WEBHOOK_SECRET,
            plans={"pro": StripePlan(name="pro", price_id="price_pro")},
            on_subscription_update=on_update,
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
    driver = ASGIDriver(app=auth.router.mount())
    user = await _sign_up(driver, email="upd@email.com")
    user_id = user["user"]["id"]
    await _link_customer(auth, user_id, "cus_upd")
    await _seed_db_subscription(
        auth, reference_id=user_id, customer_id="cus_upd", sub_id="sub_upd"
    )

    event, headers = _signed(
        {
            "id": "evt_upd",
            "type": "customer.subscription.updated",
            "data": {
                "object": {
                    "id": "sub_upd",
                    "customer": "cus_upd",
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
                    "metadata": {},
                }
            },
        }
    )
    r = await driver.request(
        "POST", "/stripe/webhook", json_body=event, headers=headers
    )
    assert r.status == 200, r.json()
    assert "update" in captured
    payload = captured["update"]
    assert payload["subscription"]["stripeSubscriptionId"] == "sub_upd"
    assert payload["stripeSubscription"]["id"] == "sub_upd"


async def test_subscription_updated_webhook_syncs_schedule_id() -> None:
    """A `schedule` on the Stripe object is mirrored to stripeScheduleId, and
    cleared when the schedule is removed."""
    driver, mock, auth = _make_driver()
    user = await _sign_up(driver, email="sched@email.com")
    user_id = user["user"]["id"]
    await _link_customer(auth, user_id, "cus_sched")
    await _seed_db_subscription(
        auth, reference_id=user_id, customer_id="cus_sched", sub_id="sub_sched"
    )

    base_item = {
        "price": {"id": "price_pro"},
        "current_period_start": 1700000000,
        "current_period_end": 1700000000 + 30 * 86400,
        "quantity": 1,
    }

    event, headers = _signed(
        {
            "id": "evt_sched_set",
            "type": "customer.subscription.updated",
            "data": {
                "object": {
                    "id": "sub_sched",
                    "customer": "cus_sched",
                    "status": "active",
                    "schedule": "sub_sched_sched_1",
                    "items": {"data": [base_item]},
                    "metadata": {},
                }
            },
        }
    )
    r = await driver.request(
        "POST", "/stripe/webhook", json_body=event, headers=headers
    )
    assert r.status == 200, r.json()

    from kernia.types.adapter import Where

    row = await auth.context.adapter.find_one(
        model="subscription",
        where=(Where(field="stripeSubscriptionId", value="sub_sched"),),
    )
    assert row["stripeScheduleId"] == "sub_sched_sched_1"

    # Now remove the schedule → column must clear.
    event, headers = _signed(
        {
            "id": "evt_sched_clear",
            "type": "customer.subscription.updated",
            "data": {
                "object": {
                    "id": "sub_sched",
                    "customer": "cus_sched",
                    "status": "active",
                    "items": {"data": [base_item]},
                    "metadata": {},
                }
            },
        }
    )
    r = await driver.request(
        "POST", "/stripe/webhook", json_body=event, headers=headers
    )
    assert r.status == 200, r.json()
    row = await auth.context.adapter.find_one(
        model="subscription",
        where=(Where(field="stripeSubscriptionId", value="sub_sched"),),
    )
    assert row["stripeScheduleId"] is None


# ----- free-trial lifecycle parity -----------------------------------------


async def test_free_trial_on_trial_end_fires_on_active_transition() -> None:
    """A trialing→active update triggers the plan's onTrialEnd hook."""
    from kernia_stripe import FreeTrial

    fired: dict[str, object] = {}

    async def on_trial_end(data: dict[str, object], _ctx: object) -> None:
        fired["end"] = data

    mock = MockStripe()
    client = StripeClient(api_key="sk_test_x", transport=mock.mock_transport())
    plugin = stripe(
        StripeOptions(
            stripe_client=client,
            webhook_secret=WEBHOOK_SECRET,
            plans={
                "pro": StripePlan(
                    name="pro",
                    price_id="price_pro",
                    free_trial=FreeTrial(days=14, on_trial_end=on_trial_end),
                )
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
    driver = ASGIDriver(app=auth.router.mount())
    user = await _sign_up(driver, email="trial@email.com")
    user_id = user["user"]["id"]
    await _link_customer(auth, user_id, "cus_trial")
    await _seed_db_subscription(
        auth,
        reference_id=user_id,
        customer_id="cus_trial",
        sub_id="sub_trial",
        status="trialing",
    )

    event, headers = _signed(
        {
            "id": "evt_trial_end",
            "type": "customer.subscription.updated",
            "data": {
                "object": {
                    "id": "sub_trial",
                    "customer": "cus_trial",
                    "status": "active",
                    "items": {"data": [{"price": {"id": "price_pro"}, "quantity": 1}]},
                    "metadata": {},
                }
            },
        }
    )
    r = await driver.request(
        "POST", "/stripe/webhook", json_body=event, headers=headers
    )
    assert r.status == 200, r.json()
    assert "end" in fired
    assert fired["end"]["subscription"]["stripeSubscriptionId"] == "sub_trial"


# ----- restore vs resume parity --------------------------------------------


async def test_restore_clears_pending_cancel_via_stripe_update() -> None:
    """`/subscription/restore` lifts a pending cancel and clears the row flags."""
    driver, mock, auth = _make_driver()
    user = await _sign_up(driver, email="restore@email.com")
    user_id = user["user"]["id"]
    await _link_customer(auth, user_id, "cus_restore")
    await _seed_db_subscription(
        auth,
        reference_id=user_id,
        customer_id="cus_restore",
        sub_id="sub_restore",
        cancelAtPeriodEnd=True,
    )
    mock.subscriptions["sub_restore"] = {
        "id": "sub_restore",
        "object": "subscription",
        "customer": "cus_restore",
        "status": "active",
        "cancel_at_period_end": True,
        "items": {"data": [{"price": {"id": "price_pro"}, "quantity": 1}]},
    }

    r = await driver.request(
        "POST",
        "/subscription/restore",
        json_body={"subscriptionId": "sub_restore"},
    )
    assert r.status == 200, r.json()
    # Stripe-side flag was cleared by the plugin.
    assert mock.subscriptions["sub_restore"]["cancel_at_period_end"] is False

    from kernia.types.adapter import Where

    row = await auth.context.adapter.find_one(
        model="subscription",
        where=(Where(field="stripeSubscriptionId", value="sub_restore"),),
    )
    assert row["cancelAtPeriodEnd"] is False


async def test_restore_rejects_when_no_pending_change() -> None:
    """Restoring a subscription with nothing pending is a 400."""
    driver, mock, auth = _make_driver()
    user = await _sign_up(driver, email="restore-noop@email.com")
    user_id = user["user"]["id"]
    await _link_customer(auth, user_id, "cus_restore_noop")
    await _seed_db_subscription(
        auth,
        reference_id=user_id,
        customer_id="cus_restore_noop",
        sub_id="sub_restore_noop",
    )
    mock.subscriptions["sub_restore_noop"] = {
        "id": "sub_restore_noop",
        "object": "subscription",
        "customer": "cus_restore_noop",
        "status": "active",
        "cancel_at_period_end": False,
        "items": {"data": [{"price": {"id": "price_pro"}, "quantity": 1}]},
    }

    r = await driver.request(
        "POST",
        "/subscription/restore",
        json_body={"subscriptionId": "sub_restore_noop"},
    )
    assert r.status == 400
    assert r.json()["code"] == "SUBSCRIPTION_NOT_PENDING_CHANGE"


async def test_resume_clears_cancel_flag_immediately() -> None:
    """`/stripe/resume-subscription` immediately clears cancel_at_period_end."""
    driver, mock, auth = _make_driver()
    user = await _sign_up(driver, email="resume@email.com")
    user_id = user["user"]["id"]
    await _link_customer(auth, user_id, "cus_resume")
    await _seed_db_subscription(
        auth,
        reference_id=user_id,
        customer_id="cus_resume",
        sub_id="sub_resume",
        cancelAtPeriodEnd=True,
    )
    mock.subscriptions["sub_resume"] = {
        "id": "sub_resume",
        "object": "subscription",
        "customer": "cus_resume",
        "status": "active",
        "cancel_at_period_end": True,
        "items": {"data": [{"price": {"id": "price_pro"}, "quantity": 1}]},
    }

    r = await driver.request(
        "POST",
        "/stripe/resume-subscription",
        json_body={"subscriptionId": "sub_resume"},
    )
    assert r.status == 200, r.json()
    assert mock.subscriptions["sub_resume"]["cancel_at_period_end"] is False

    from kernia.types.adapter import Where

    row = await auth.context.adapter.find_one(
        model="subscription",
        where=(Where(field="stripeSubscriptionId", value="sub_resume"),),
    )
    assert row["cancelAtPeriodEnd"] is False


# ----- customer search → list fallback parity ------------------------------


async def test_checkout_reuses_existing_customer_via_search() -> None:
    """When a Stripe customer already exists for the email, checkout reuses it
    (customers.search) instead of creating a new one."""
    # Disable createCustomerOnSignUp so the user has no stripeCustomerId yet —
    # checkout must then resolve the existing customer via customers.search.
    driver, mock, auth = _make_driver(create_customer_on_sign_up=False)
    await _sign_up(driver, email="reuse@example.com")

    # Pre-seed an existing Stripe customer for the same email.
    existing_id = "cus_preexisting"
    mock.customers[existing_id] = {
        "id": existing_id,
        "object": "customer",
        "email": "reuse@example.com",
        "metadata": {"customerType": "user"},
    }

    r = await driver.request(
        "POST",
        "/stripe/checkout-session",
        json_body={
            "plan": "pro",
            "successUrl": "https://app.test/s",
            "cancelUrl": "https://app.test/c",
        },
    )
    assert r.status == 200, r.json()
    # No new customer.create was captured — the existing one was reused.
    assert all(e["type"] != "customer.create" for e in mock.capture_events)
    session_event = next(
        e for e in mock.capture_events if e["type"] == "checkout.session.create"
    )
    assert session_event["object"]["customer"] == existing_id


async def test_checkout_falls_back_to_list_when_search_unavailable() -> None:
    """If customers.search is unavailable, checkout falls back to customers.list."""
    driver, mock, auth = _make_driver(create_customer_on_sign_up=False)
    mock.search_unavailable = True
    await _sign_up(driver, email="fallback@example.com")

    existing_id = "cus_listfound"
    mock.customers[existing_id] = {
        "id": existing_id,
        "object": "customer",
        "email": "fallback@example.com",
        "metadata": {"customerType": "user"},
    }

    r = await driver.request(
        "POST",
        "/stripe/checkout-session",
        json_body={
            "plan": "pro",
            "successUrl": "https://app.test/s",
            "cancelUrl": "https://app.test/c",
        },
    )
    assert r.status == 200, r.json()
    assert all(e["type"] != "customer.create" for e in mock.capture_events)
    session_event = next(
        e for e in mock.capture_events if e["type"] == "checkout.session.create"
    )
    assert session_event["object"]["customer"] == existing_id


# ----- on_customer_create + metadata parity --------------------------------


async def test_on_customer_create_hook_and_metadata() -> None:
    """Creating a customer fires on_customer_create and stamps userId/customerType."""
    captured: dict[str, object] = {}

    async def on_customer_create(data: dict[str, object], _ctx: object) -> None:
        captured["data"] = data

    mock = MockStripe()
    client = StripeClient(api_key="sk_test_x", transport=mock.mock_transport())
    plugin = stripe(
        StripeOptions(
            stripe_client=client,
            webhook_secret=WEBHOOK_SECRET,
            plans={"pro": StripePlan(name="pro", price_id="price_pro")},
            on_customer_create=on_customer_create,
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
    driver = ASGIDriver(app=auth.router.mount())
    user = await _sign_up(driver, email="hook@example.com")
    user_id = user["user"]["id"]

    r = await driver.request(
        "POST",
        "/stripe/checkout-session",
        json_body={
            "plan": "pro",
            "successUrl": "https://app.test/s",
            "cancelUrl": "https://app.test/c",
        },
    )
    assert r.status == 200, r.json()
    assert "data" in captured
    assert captured["data"]["user"]["id"] == user_id
    create_event = next(
        e for e in mock.capture_events if e["type"] == "customer.create"
    )
    meta = create_event["object"]["metadata"]
    assert meta["userId"] == user_id
    assert meta["customerType"] == "user"
