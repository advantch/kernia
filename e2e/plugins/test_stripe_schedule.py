"""Deferred plan changes via Stripe Subscription Schedules.

Ports the schedule cases from `reference/packages/stripe/test/subscription.test.ts`:

  * `scheduleAtPeriodEnd: true` routes the plan change through Subscription
    Schedules (create `from_subscription`, then a two-phase update with
    `end_behavior: release` and a deferred phase using `proration_behavior:
    "none"`) instead of an immediate proration update; the DB row keeps its
    current plan and stores `stripeScheduleId`.
  * Any *plugin-created* schedule (`metadata.source == "@better-auth/stripe"`)
    attached to the subscription is released before a new change is applied.
  * Schedules created outside the plugin are left untouched.

Divergence note: the Python port applies *immediate* upgrades through a direct
`subscriptions.update` proration call (see `test_stripe.py`), whereas upstream
prefers the Billing Portal for single-item immediate changes. The
release-vs-don't-release behaviour these tests assert is identical; the two
immediate-path tests assert the Python contract (`subscription.update`) rather
than `billingPortal.sessions.create`.
"""

from __future__ import annotations

from kernia.auth import init
from kernia.plugins import email_and_password
from kernia.types.adapter import Where
from kernia.types.init_options import (
    EmailPasswordOptions,
    KerniaOptions,
    RateLimitOptions,
)
from kernia_memory_adapter import memory_adapter
from kernia_stripe import StripeClient, StripeOptions, StripePlan, stripe
from kernia_test_utils import ASGIDriver, MockStripe

WEBHOOK_SECRET = "whsec_test_secret"
CUSTOMER_ID = "cus_mock123"


def _build() -> tuple[ASGIDriver, MockStripe, object]:
    mock = MockStripe()
    mock.add_price("price_starter", usage_type="licensed")
    mock.add_price("price_premium", usage_type="licensed")
    client = StripeClient(api_key="sk_test_x", transport=mock.mock_transport())
    plugin = stripe(
        StripeOptions(
            stripe_client=client,
            webhook_secret=WEBHOOK_SECRET,
            plans={
                "starter": StripePlan(name="starter", price_id="price_starter"),
                "premium": StripePlan(name="premium", price_id="price_premium"),
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


async def _signup(driver: ASGIDriver, auth: object, email: str) -> str:
    r = await driver.request(
        "POST", "/sign-up/email", json_body={"email": email, "password": "longstrongpw"}
    )
    assert r.status == 200, r.json()
    user_id = r.json()["user"]["id"]
    # Link the Stripe customer so /subscription/upgrade reuses it.
    await auth.context.adapter.update(  # type: ignore[attr-defined]
        model="user",
        where=(Where(field="id", value=user_id),),
        update={"stripeCustomerId": CUSTOMER_ID},
    )
    return user_id


async def _seed_db_sub(auth: object, *, user_id: str, plan: str, stripe_sub_id: str) -> None:
    await auth.context.adapter.create(  # type: ignore[attr-defined]
        model="subscription",
        data={
            "plan": plan,
            "referenceId": user_id,
            "status": "active",
            "stripeSubscriptionId": stripe_sub_id,
            "stripeCustomerId": CUSTOMER_ID,
        },
    )


def _events(mock: MockStripe, kind: str) -> list[dict]:
    return [e for e in mock.capture_events if e["type"] == kind]


async def test_schedules_plan_change_at_period_end() -> None:
    driver, mock, auth = _build()
    user_id = await _signup(driver, auth, "schedule-downgrade@email.com")
    await _seed_db_sub(auth, user_id=user_id, plan="premium", stripe_sub_id="sub_schedule_test")
    mock.add_subscription(
        "sub_schedule_test", customer=CUSTOMER_ID, items=[{"price": "price_premium"}]
    )

    r = await driver.request(
        "POST",
        "/subscription/upgrade",
        json_body={"plan": "starter", "scheduleAtPeriodEnd": True},
    )
    assert r.status == 200, r.json()

    # Routed through Subscription Schedules, not billing portal / checkout /
    # immediate subscriptions.update.
    create = _events(mock, "subscription_schedule.create")
    assert len(create) == 1
    assert create[0]["params"]["from_subscription"] == "sub_schedule_test"

    update = _events(mock, "subscription_schedule.update")
    assert len(update) == 1
    p = update[0]["params"]
    assert p["metadata[source]"] == "@better-auth/stripe"
    assert p["end_behavior"] == "release"
    # Deferred (second) phase uses no proration; the new plan price appears.
    assert p["phases[1][proration_behavior]"] == "none"
    assert p["phases[1][items][0][price]"] == "price_starter"

    assert not _events(mock, "billing_portal.session.create")
    assert not _events(mock, "checkout.session.create")
    assert not _events(mock, "subscription.update")

    # Plan stays premium (webhook applies the change later); schedule id stored.
    row = await auth.context.adapter.find_one(  # type: ignore[attr-defined]
        model="subscription",
        where=(Where(field="referenceId", value=user_id),),
    )
    assert row["plan"] == "premium"
    assert row["stripeScheduleId"] == create[0]["object"]["id"]

    body = r.json()
    assert body["url"] is not None
    assert body["redirect"] is True


async def test_releases_existing_plugin_schedule_before_scheduling_new() -> None:
    driver, mock, auth = _build()
    user_id = await _signup(driver, auth, "release-schedule@email.com")
    await _seed_db_sub(auth, user_id=user_id, plan="premium", stripe_sub_id="sub_with_schedule")
    mock.add_subscription(
        "sub_with_schedule",
        customer=CUSTOMER_ID,
        items=[{"price": "price_premium"}],
        schedule="sub_sched_existing",
    )
    mock.add_schedule(
        "sub_sched_existing",
        subscription="sub_with_schedule",
        customer=CUSTOMER_ID,
        metadata={"source": "@better-auth/stripe"},
    )

    r = await driver.request(
        "POST",
        "/subscription/upgrade",
        json_body={"plan": "starter", "scheduleAtPeriodEnd": True},
    )
    assert r.status == 200, r.json()

    released = _events(mock, "subscription_schedule.release")
    assert any(e["object"]["id"] == "sub_sched_existing" for e in released)

    create = _events(mock, "subscription_schedule.create")
    assert create and create[0]["params"]["from_subscription"] == "sub_with_schedule"


async def test_releases_existing_plugin_schedule_before_immediate_upgrade() -> None:
    driver, mock, auth = _build()
    user_id = await _signup(driver, auth, "release-then-upgrade@email.com")
    await _seed_db_sub(
        auth, user_id=user_id, plan="starter", stripe_sub_id="sub_scheduled_then_upgrade"
    )
    mock.add_subscription(
        "sub_scheduled_then_upgrade",
        customer=CUSTOMER_ID,
        items=[{"price": "price_starter"}],
        schedule="sub_schedule_old",
    )
    mock.add_schedule(
        "sub_schedule_old",
        subscription="sub_scheduled_then_upgrade",
        customer=CUSTOMER_ID,
        metadata={"source": "@better-auth/stripe"},
    )

    r = await driver.request("POST", "/subscription/upgrade", json_body={"plan": "premium"})
    assert r.status == 200, r.json()

    released = _events(mock, "subscription_schedule.release")
    assert any(e["object"]["id"] == "sub_schedule_old" for e in released)

    # Immediate upgrade applies via subscriptions.update (Python contract), and
    # does not create a new schedule.
    assert _events(mock, "subscription.update")
    assert not _events(mock, "subscription_schedule.create")


async def test_does_not_release_externally_created_schedule() -> None:
    driver, mock, auth = _build()
    user_id = await _signup(driver, auth, "external-schedule@email.com")
    await _seed_db_sub(auth, user_id=user_id, plan="starter", stripe_sub_id="sub_external_schedule")
    mock.add_subscription(
        "sub_external_schedule",
        customer=CUSTOMER_ID,
        items=[{"price": "price_starter"}],
        schedule="sub_sched_external",
    )
    mock.add_schedule(
        "sub_sched_external",
        subscription="sub_external_schedule",
        customer=CUSTOMER_ID,
        metadata={},  # no source field → not plugin-owned
    )

    r = await driver.request("POST", "/subscription/upgrade", json_body={"plan": "premium"})
    assert r.status == 200, r.json()

    # External schedule must NOT be released.
    assert not _events(mock, "subscription_schedule.release")
    # Upgrade still proceeds (Python immediate path uses subscriptions.update).
    assert _events(mock, "subscription.update")
