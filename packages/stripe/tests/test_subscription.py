"""Ported from reference/packages/stripe/test/subscription.test.ts.

A focused subset of the upstream `stripe subscription` describe block, covering
the behavior the Python port implements: the no-active-subscription upgrade
(creates an `incomplete` row + checkout session), cross-reference isolation,
metadata pass-through, and `subscription.list` filtering / priceId resolution.

Cases that depend on features the Python port does not implement (subscription
schedules, line-item multiset diffing, trial-abuse propagation from Stripe
events, flexible `limits` typing) are intentionally NOT ported here; see the
parity report.
"""

from __future__ import annotations

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
PASSWORD = "password123"


def _make(plans: dict[str, StripePlan] | None = None) -> tuple[ASGIDriver, MockStripe, Any]:
    mock = MockStripe()
    client = StripeClient(api_key="sk_test", transport=mock.mock_transport())
    opts = StripeOptions(
        stripe_client=client,
        webhook_secret=WEBHOOK_SECRET,
        create_customer_on_sign_up=True,
        plans=plans
        or {
            "starter": StripePlan(
                name="starter", price_id="price_test_1", lookup_key="lookup_key_123"
            ),
            "premium": StripePlan(
                name="premium", price_id="price_test_2", lookup_key="lookup_key_234"
            ),
        },
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


async def _signup_signin(driver: ASGIDriver, email: str) -> str:
    r = await driver.request(
        "POST",
        "/sign-up/email",
        json_body={"email": email, "password": PASSWORD, "name": "Test User"},
    )
    assert r.status == 200, r.json()
    uid = r.json()["user"]["id"]
    r = await driver.request(
        "POST", "/sign-in/email", json_body={"email": email, "password": PASSWORD}
    )
    assert r.status == 200, r.json()
    return uid


async def test_creates_an_incomplete_subscription_on_upgrade() -> None:
    driver, _mock, auth = _make()
    uid = await _signup_signin(driver, "create-sub@email.com")

    r = await driver.request(
        "POST", "/subscription/upgrade", json_body={"plan": "starter"}
    )
    assert r.status == 200, r.json()
    assert r.json().get("url")

    sub = await auth.context.adapter.find_one(
        model="subscription", where=(Where(field="referenceId", value=uid),)
    )
    assert sub["plan"] == "starter"
    assert sub["referenceId"] == uid
    assert sub["stripeCustomerId"]
    assert sub["status"] == "incomplete"
    assert sub["cancelAtPeriodEnd"] is False
    assert sub.get("trialStart") is None
    assert sub.get("trialEnd") is None


async def test_disallows_cross_user_subscription_id_operations() -> None:
    driver, mock, auth = _make()
    uid_a = await _signup_signin(driver, "user-a@email.com")
    await driver.request(
        "POST", "/subscription/upgrade", json_body={"plan": "starter"}
    )
    sub_a = await auth.context.adapter.find_one(
        model="subscription", where=(Where(field="referenceId", value=uid_a),)
    )
    assert sub_a is not None
    # Give it a real Stripe subscription id so the lookup can find it by id but
    # still reject due to reference mismatch.
    await auth.context.adapter.update(
        model="subscription",
        where=(Where(field="id", value=sub_a["id"]),),
        update={"stripeSubscriptionId": "sub_user_a", "status": "active"},
    )

    # User B signs in (new session replaces the cookie) and tries to operate on
    # user A's subscription.
    await _signup_signin(driver, "user-b@email.com")

    before = len([e for e in mock.capture_events if e["type"] == "checkout.session.create"])
    up = await driver.request(
        "POST",
        "/subscription/upgrade",
        json_body={"plan": "premium", "subscriptionId": "sub_user_a"},
    )
    assert up.status >= 400
    assert up.json()["code"] == "SUBSCRIPTION_NOT_FOUND"

    cancel = await driver.request(
        "POST",
        "/subscription/cancel",
        json_body={"subscriptionId": "sub_user_a", "returnUrl": "/account"},
    )
    assert cancel.status == 400
    assert cancel.json()["code"] == "SUBSCRIPTION_NOT_FOUND"

    restore = await driver.request(
        "POST",
        "/subscription/restore",
        json_body={"subscriptionId": "sub_user_a"},
    )
    assert restore.status == 400
    assert restore.json()["code"] == "SUBSCRIPTION_NOT_FOUND"

    # No billing portal / extra checkout session was created for user B.
    after = len([e for e in mock.capture_events if e["type"] == "checkout.session.create"])
    assert after == before
    assert all(
        e["type"] != "billing_portal.session.create" for e in mock.capture_events
    )


async def test_passes_metadata_to_checkout_when_upgrading() -> None:
    driver, mock, _auth = _make()
    await _signup_signin(driver, "metadata-test@email.com")

    custom = {
        "customField": "customValue",
        "organizationId": "org_123",
        "projectId": "proj_456",
    }
    r = await driver.request(
        "POST",
        "/subscription/upgrade",
        json_body={"plan": "starter", "metadata": custom},
    )
    assert r.status == 200, r.json()

    session_event = next(
        e for e in mock.capture_events if e["type"] == "checkout.session.create"
    )
    meta = session_event["object"]["metadata"]
    for key, value in custom.items():
        assert meta[key] == value


async def test_list_filters_to_active_subscriptions() -> None:
    driver, _mock, auth = _make()
    uid = await _signup_signin(driver, "list-test@email.com")

    r = await driver.request("GET", "/subscription/list")
    assert r.status == 200
    assert isinstance(r.json(), list)

    await driver.request(
        "POST", "/subscription/upgrade", json_body={"plan": "starter"}
    )
    # The new row is `incomplete` → not listed.
    r = await driver.request("GET", "/subscription/list")
    assert r.json() == []

    await auth.context.adapter.update(
        model="subscription",
        where=(Where(field="referenceId", value=uid),),
        update={"status": "active"},
    )
    r = await driver.request("GET", "/subscription/list")
    assert len(r.json()) > 0


async def test_list_resolves_annual_discount_price_id_by_billing_interval() -> None:
    driver, _mock, auth = _make(
        plans={
            "starter": StripePlan(
                name="starter",
                price_id="price_monthly_starter",
                annual_discount_price_id="price_annual_starter",
            ),
            "premium": StripePlan(name="premium", price_id="price_test_2"),
        }
    )
    uid = await _signup_signin(driver, "annual-test@email.com")
    await driver.request(
        "POST", "/subscription/upgrade", json_body={"plan": "starter"}
    )

    await auth.context.adapter.update(
        model="subscription",
        where=(Where(field="referenceId", value=uid),),
        update={"status": "active", "billingInterval": "year"},
    )
    r = await driver.request("GET", "/subscription/list")
    rows = r.json()
    assert len(rows) > 0
    assert rows[0]["priceId"] == "price_annual_starter"

    await auth.context.adapter.update(
        model="subscription",
        where=(Where(field="referenceId", value=uid),),
        update={"billingInterval": "month"},
    )
    r = await driver.request("GET", "/subscription/list")
    assert r.json()[0]["priceId"] == "price_monthly_starter"


async def test_list_returns_billing_interval() -> None:
    driver, _mock, auth = _make()
    uid = await _signup_signin(driver, "billing-interval@example.com")
    await auth.context.adapter.create(
        model="subscription",
        data={
            "referenceId": uid,
            "stripeCustomerId": "cus_1",
            "stripeSubscriptionId": "sub_1",
            "status": "active",
            "plan": "starter",
            "billingInterval": "year",
            "createdAt": 1,
            "updatedAt": 1,
        },
    )
    r = await driver.request("GET", "/subscription/list")
    assert r.json()[0]["billingInterval"] == "year"
