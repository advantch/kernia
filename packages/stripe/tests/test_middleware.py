"""Ported from reference/packages/stripe/test/middleware.test.ts.

Covers `referenceMiddleware` authorization on `/subscription/upgrade` for both
user and organization customer types. Kept ~1:1 with the upstream describe
blocks. Upstream drives this through `client.subscription.upgrade(...)`; here we
POST to `/subscription/upgrade` through the ASGI driver, which persists the
session cookie set on sign-in.

The "pass" cases exercise the no-active-subscription path: the upgrade endpoint
creates an `incomplete` subscription row and opens a Stripe Checkout session,
returning `{url, redirect}`.
"""

from __future__ import annotations

from typing import Any

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
from kernia_stripe.schema import OrganizationStripeOptions
from kernia_test_utils import ASGIDriver, MockStripe

WEBHOOK_SECRET = "test_secret"
PASSWORD = "password123"


def _make(*, with_org_plugin: bool = False, **overrides: Any) -> tuple[ASGIDriver, MockStripe, Any]:
    mock = MockStripe()
    client = StripeClient(api_key="sk_test", transport=mock.mock_transport())
    opts = StripeOptions(
        stripe_client=client,
        webhook_secret=WEBHOOK_SECRET,
        create_customer_on_sign_up=True,
        plans={
            "starter": StripePlan(name="starter", price_id="price_test_1"),
            "premium": StripePlan(name="premium", price_id="price_test_2"),
        },
        **overrides,
    )
    plugins: list[Any] = [email_and_password()]
    if with_org_plugin:
        # When the stripe plugin extends the `organization` model, that model
        # must exist — so load the organization plugin alongside it. Upstream's
        # core tolerates extending an absent model; this port does not.
        from kernia.plugins import organization

        plugins.append(organization())
    plugins.append(stripe(opts))
    auth = init(
        KerniaOptions(
            database=memory_adapter(),
            secret="stripe-secret",
            email_and_password=EmailPasswordOptions(enabled=True),
            plugins=plugins,
            rate_limit=RateLimitOptions(enabled=False),
        )
    )
    return ASGIDriver(app=auth.router.mount()), mock, auth


async def _sign_up(driver: ASGIDriver, email: str) -> str:
    r = await driver.request(
        "POST",
        "/sign-up/email",
        json_body={"email": email, "password": PASSWORD, "name": "Test User"},
    )
    assert r.status == 200, r.json()
    return r.json()["user"]["id"]


async def _sign_in(driver: ASGIDriver, email: str) -> None:
    r = await driver.request(
        "POST", "/sign-in/email", json_body={"email": email, "password": PASSWORD}
    )
    assert r.status == 200, r.json()


# ----- referenceMiddleware - user subscription -----------------------------


async def test_passes_when_no_explicit_reference_id() -> None:
    driver, _mock, _auth = _make()
    await _sign_up(driver, "ref-1@example.com")
    await _sign_in(driver, "ref-1@example.com")

    r = await driver.request("POST", "/subscription/upgrade", json_body={"plan": "starter"})
    assert r.status == 200, r.json()
    assert r.json().get("url")


async def test_passes_when_reference_id_equals_user_id() -> None:
    driver, _mock, _auth = _make()
    uid = await _sign_up(driver, "ref-2@example.com")
    await _sign_in(driver, "ref-2@example.com")

    r = await driver.request(
        "POST",
        "/subscription/upgrade",
        json_body={"plan": "starter", "referenceId": uid},
    )
    assert r.status == 200, r.json()
    assert r.json().get("url")


async def test_rejects_other_reference_id_without_authorize_reference() -> None:
    driver, _mock, _auth = _make()
    await _sign_up(driver, "ref-3@example.com")
    target = await _sign_up(driver, "ref-target-3@example.com")
    await _sign_in(driver, "ref-3@example.com")

    r = await driver.request(
        "POST",
        "/subscription/upgrade",
        json_body={"plan": "starter", "referenceId": target},
    )
    assert r.json()["code"] == "REFERENCE_ID_NOT_ALLOWED"


async def test_rejects_other_reference_id_when_authorize_returns_false() -> None:
    async def authorize_reference(_data: Any, _ctx: Any = None) -> bool:
        return False

    driver, _mock, _auth = _make(authorize_reference=authorize_reference)
    await _sign_up(driver, "ref-4@example.com")
    target = await _sign_up(driver, "ref-target-4@example.com")
    await _sign_in(driver, "ref-4@example.com")

    r = await driver.request(
        "POST",
        "/subscription/upgrade",
        json_body={"plan": "starter", "referenceId": target},
    )
    assert r.json()["code"] == "UNAUTHORIZED"


async def test_allows_other_reference_id_when_authorize_returns_true() -> None:
    async def authorize_reference(_data: Any, _ctx: Any = None) -> bool:
        return True

    driver, mock, auth = _make(authorize_reference=authorize_reference)
    actor = await _sign_up(driver, "ref-5@example.com")
    target = await _sign_up(driver, "ref-target-5@example.com")
    await _sign_in(driver, "ref-5@example.com")

    # Pin both Stripe customer ids so we can assert which one is used.
    await auth.context.adapter.update(
        model="user",
        where=(Where(field="id", value=actor),),
        update={"stripeCustomerId": "cus_actor_reference"},
    )
    await auth.context.adapter.update(
        model="user",
        where=(Where(field="id", value=target),),
        update={"stripeCustomerId": "cus_target_reference"},
    )

    r = await driver.request(
        "POST",
        "/subscription/upgrade",
        json_body={"plan": "starter", "referenceId": target},
    )
    assert r.status == 200, r.json()
    assert r.json().get("url")

    # The checkout session must use the *actor's* customer, not the target's.
    session_event = next(e for e in mock.capture_events if e["type"] == "checkout.session.create")
    assert session_event["object"]["customer"] == "cus_actor_reference"
    meta = session_event["object"]["metadata"]
    assert meta["userId"] == actor
    assert meta["referenceId"] == target

    sub = await auth.context.adapter.find_one(
        model="subscription",
        where=(Where(field="referenceId", value=target),),
    )
    assert sub["referenceId"] == target
    assert sub["status"] == "incomplete"


# ----- referenceMiddleware - organization subscription ---------------------


async def test_org_rejects_when_authorize_reference_not_defined() -> None:
    driver, _mock, _auth = _make()
    await _sign_up(driver, "org-1@example.com")
    await _sign_in(driver, "org-1@example.com")

    r = await driver.request(
        "POST",
        "/subscription/upgrade",
        json_body={
            "plan": "starter",
            "customerType": "organization",
            "referenceId": "org_123",
        },
    )
    assert r.json()["code"] == "AUTHORIZE_REFERENCE_REQUIRED"


async def test_org_rejects_when_no_reference_id() -> None:
    async def authorize_reference(_data: Any, _ctx: Any = None) -> bool:
        return True

    driver, _mock, _auth = _make(authorize_reference=authorize_reference)
    await _sign_up(driver, "org-2@example.com")
    await _sign_in(driver, "org-2@example.com")

    r = await driver.request(
        "POST",
        "/subscription/upgrade",
        json_body={"plan": "starter", "customerType": "organization"},
    )
    assert r.json()["code"] == "ORGANIZATION_REFERENCE_ID_REQUIRED"


async def test_org_rejects_when_authorize_returns_false() -> None:
    async def authorize_reference(_data: Any, _ctx: Any = None) -> bool:
        return False

    driver, _mock, _auth = _make(authorize_reference=authorize_reference)
    await _sign_up(driver, "org-3@example.com")
    await _sign_in(driver, "org-3@example.com")

    r = await driver.request(
        "POST",
        "/subscription/upgrade",
        json_body={
            "plan": "starter",
            "customerType": "organization",
            "referenceId": "org_123",
        },
    )
    assert r.json()["code"] == "UNAUTHORIZED"


async def test_org_passes_when_authorize_returns_true() -> None:
    async def authorize_reference(_data: Any, _ctx: Any = None) -> bool:
        return True

    driver, _mock, _auth = _make(
        with_org_plugin=True,
        authorize_reference=authorize_reference,
        organization=OrganizationStripeOptions(enabled=True),
    )
    await _sign_up(driver, "org-4@example.com")
    await _sign_in(driver, "org-4@example.com")

    r = await driver.request(
        "POST",
        "/subscription/upgrade",
        json_body={
            "plan": "starter",
            "customerType": "organization",
            "referenceId": "org_123",
        },
    )
    # Should pass middleware authorization. May fail later for unrelated
    # reasons, but never with these two codes.
    code = r.json().get("code") if r.status >= 400 else None
    assert code != "ORGANIZATION_SUBSCRIPTION_NOT_ENABLED"
    assert code != "UNAUTHORIZED"
