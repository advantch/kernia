"""Organization-scoped Stripe customer + subscription flows.

Ports the distinct behaviors of the `describe("stripe - organization customer")`
block of `reference/packages/stripe/test/stripe-organization.test.ts`:

  * upgrading a subscription for an organization creates a Stripe customer named
    after the org (with ``organizationId`` + ``customerType`` metadata), writes
    the new ``stripeCustomerId`` back onto the org row, and fires
    ``organization.on_customer_create``.
  * an org that already has a ``stripeCustomerId`` is reused (no new customer).
  * ``organization.get_customer_create_params`` is invoked with the org and its
    return value is merged into the ``customers.create`` call.
  * billing-portal sessions for an org use the org's customer id.
  * user and organization subscriptions stay isolated (``/subscription/list``
    filtered by ``referenceId`` + ``customerType``).
  * error paths: ``ORGANIZATION_NOT_FOUND`` for a missing org, and
    ``AUTHORIZE_REFERENCE_REQUIRED`` when neither org integration nor
    ``authorize_reference`` is configured.
"""

from __future__ import annotations

from typing import Any

from kernia.auth import init
from kernia.plugins.email_password import email_and_password
from kernia.plugins.organization import organization
from kernia.types.adapter import Where
from kernia.types.init_options import (
    KerniaOptions,
    EmailPasswordOptions,
    RateLimitOptions,
)
from kernia_memory_adapter import memory_adapter
from kernia_stripe import StripeClient, StripeOptions, StripePlan, stripe
from kernia_stripe.schema import OrganizationStripeOptions
from kernia_test_utils import ASGIDriver, MockStripe

WEBHOOK_SECRET = "whsec_test_secret"


def _plans() -> dict[str, StripePlan]:
    return {
        "starter": StripePlan(name="starter", price_id="price_starter"),
        "premium": StripePlan(name="premium", price_id="price_premium"),
    }


def _build(
    org_opts: OrganizationStripeOptions | None = None,
    *,
    with_org_plugin: bool = True,
    authorize_reference: Any | None = lambda *_a, **_k: True,
) -> tuple[ASGIDriver, MockStripe, object]:
    mock = MockStripe()
    mock.add_price("price_starter", usage_type="licensed")
    mock.add_price("price_premium", usage_type="licensed")
    client = StripeClient(api_key="sk_test_x", transport=mock.mock_transport())
    plugin = stripe(
        StripeOptions(
            stripe_client=client,
            webhook_secret=WEBHOOK_SECRET,
            create_customer_on_sign_up=False,
            plans=_plans(),
            organization=org_opts,
            authorize_reference=authorize_reference,
        )
    )
    plugins: list[Any] = [email_and_password()]
    if with_org_plugin:
        plugins.append(organization())
    plugins.append(plugin)
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


async def _signup(driver: ASGIDriver, email: str) -> str:
    r = await driver.request(
        "POST",
        "/sign-up/email",
        json_body={"email": email, "password": "longstrongpw", "name": email},
    )
    assert r.status == 200, r.json()
    return r.json()["user"]["id"]


async def _create_org(driver: ASGIDriver, *, name: str, slug: str) -> str:
    r = await driver.request(
        "POST", "/organization/create", json_body={"name": name, "slug": slug}
    )
    assert r.status == 200, r.json()
    return r.json()["id"]


async def _upgrade(driver: ASGIDriver, *, plan: str, org_id: str) -> Any:
    return await driver.request(
        "POST",
        "/subscription/upgrade",
        json_body={
            "plan": plan,
            "customerType": "organization",
            "referenceId": org_id,
        },
    )


def _customer_creates(mock: MockStripe) -> list[dict[str, Any]]:
    return [e for e in mock.capture_events if e["type"] == "customer.create"]


def _checkout_params(mock: MockStripe) -> dict[str, Any]:
    evs = [e for e in mock.capture_events if e["type"] == "checkout.session.create"]
    assert evs, "expected a checkout session"
    return evs[-1]["params"]


# ---------------------------------------------------------------------------
# customer creation on upgrade
# ---------------------------------------------------------------------------


async def test_creates_stripe_customer_for_organization_on_upgrade() -> None:
    seen: list[dict[str, Any]] = []

    async def on_customer_create(data: dict[str, Any], *_a: Any) -> None:
        seen.append(data)

    driver, mock, auth = _build(
        OrganizationStripeOptions(enabled=True, on_customer_create=on_customer_create)
    )
    adapter = auth.context.adapter  # type: ignore[attr-defined]
    await _signup(driver, "org-customer-test@email.com")
    org_id = await _create_org(driver, name="Test Organization", slug="test-org")

    r = await _upgrade(driver, plan="starter", org_id=org_id)
    assert r.status == 200, r.json()
    assert r.json()["url"] is not None

    creates = _customer_creates(mock)
    assert len(creates) == 1
    obj = creates[0]["object"]
    assert obj["name"] == "Test Organization"
    assert obj["metadata"]["organizationId"] == org_id
    assert obj["metadata"]["customerType"] == "organization"

    org_row = await adapter.find_one(
        model="organization", where=(Where(field="id", value=org_id),)
    )
    assert org_row["stripeCustomerId"] == obj["id"]

    assert seen, "on_customer_create was not called"
    assert seen[0]["stripeCustomer"]["id"] == obj["id"]
    assert seen[0]["organization"]["id"] == org_id


async def test_reuses_existing_org_stripe_customer_id() -> None:
    driver, mock, auth = _build(OrganizationStripeOptions(enabled=True))
    adapter = auth.context.adapter  # type: ignore[attr-defined]
    await _signup(driver, "org-existing-customer@email.com")
    org_id = await _create_org(driver, name="Existing Stripe Org", slug="existing-org")
    await adapter.update(
        model="organization",
        where=(Where(field="id", value=org_id),),
        update={"stripeCustomerId": "cus_existing_org_123"},
    )

    r = await _upgrade(driver, plan="starter", org_id=org_id)
    assert r.status == 200, r.json()

    assert not _customer_creates(mock), "should not create a new customer"
    assert _checkout_params(mock)["customer"] == "cus_existing_org_123"


async def test_calls_get_customer_create_params_for_org() -> None:
    received: list[Any] = []

    async def get_params(org: Any, *_a: Any, **_k: Any) -> dict[str, Any]:
        received.append(org)
        return {"email": "billing@org.com", "description": "Custom org description"}

    driver, mock, auth = _build(
        OrganizationStripeOptions(enabled=True, get_customer_create_params=get_params)
    )
    await _signup(driver, "org-params-test@email.com")
    org_id = await _create_org(driver, name="Params Test Org", slug="params-test-org")

    r = await _upgrade(driver, plan="starter", org_id=org_id)
    assert r.status == 200, r.json()

    assert received and received[0]["id"] == org_id
    obj = _customer_creates(mock)[0]["object"]
    assert obj["email"] == "billing@org.com"
    assert obj["description"] == "Custom org description"


# ---------------------------------------------------------------------------
# billing portal
# ---------------------------------------------------------------------------


async def test_creates_billing_portal_for_organization() -> None:
    driver, mock, auth = _build(OrganizationStripeOptions(enabled=True))
    adapter = auth.context.adapter  # type: ignore[attr-defined]
    await _signup(driver, "org-portal-test@email.com")
    org_id = await _create_org(driver, name="Portal Test Org", slug="portal-test-org")
    await adapter.update(
        model="organization",
        where=(Where(field="id", value=org_id),),
        update={"stripeCustomerId": "cus_portal_org_123"},
    )
    await adapter.create(
        model="subscription",
        data={
            "referenceId": org_id,
            "stripeCustomerId": "cus_portal_org_123",
            "status": "active",
            "plan": "starter",
        },
    )

    r = await driver.request(
        "POST",
        "/subscription/billing-portal",
        json_body={
            "customerType": "organization",
            "referenceId": org_id,
            "returnUrl": "/dashboard",
        },
    )
    assert r.status == 200, r.json()
    assert r.json()["url"] is not None

    portals = [
        e for e in mock.capture_events if e["type"] == "billing_portal.session.create"
    ]
    assert portals, "expected a billing portal session"
    assert portals[-1]["object"]["customer"] == "cus_portal_org_123"


# ---------------------------------------------------------------------------
# isolation between user + org subscriptions
# ---------------------------------------------------------------------------


async def test_keeps_user_and_org_subscriptions_separate() -> None:
    driver, _mock, auth = _build(OrganizationStripeOptions(enabled=True))
    adapter = auth.context.adapter  # type: ignore[attr-defined]
    user_id = await _signup(driver, "separate-sub-test@email.com")
    org_id = await _create_org(driver, name="Separate Sub Org", slug="separate-org")
    await adapter.update(
        model="organization",
        where=(Where(field="id", value=org_id),),
        update={"stripeCustomerId": "cus_separate_org"},
    )
    await adapter.create(
        model="subscription",
        data={
            "referenceId": user_id,
            "stripeCustomerId": "cus_user_123",
            "stripeSubscriptionId": "sub_user_123",
            "status": "active",
            "plan": "starter",
        },
    )
    await adapter.create(
        model="subscription",
        data={
            "referenceId": org_id,
            "stripeCustomerId": "cus_separate_org",
            "stripeSubscriptionId": "sub_org_123",
            "status": "active",
            "plan": "premium",
        },
    )

    user_subs = await driver.request("GET", "/subscription/list")
    assert user_subs.status == 200, user_subs.json()
    u = user_subs.json()
    assert len(u) == 1
    assert u[0]["plan"] == "starter"
    assert u[0]["referenceId"] == user_id

    org_subs = await driver.request(
        "GET",
        "/subscription/list",
        query=f"customerType=organization&referenceId={org_id}",
    )
    assert org_subs.status == 200, org_subs.json()
    o = org_subs.json()
    assert len(o) == 1
    assert o[0]["plan"] == "premium"
    assert o[0]["referenceId"] == org_id


# ---------------------------------------------------------------------------
# error paths
# ---------------------------------------------------------------------------


async def test_organization_not_found_on_upgrade() -> None:
    driver, _mock, _auth = _build(OrganizationStripeOptions(enabled=True))
    await _signup(driver, "org-missing@email.com")

    r = await _upgrade(driver, plan="starter", org_id="does-not-exist")
    assert r.status != 200
    assert r.json()["code"] == "ORGANIZATION_NOT_FOUND"


async def test_rejects_org_subscription_without_authorize_reference() -> None:
    # No organization integration and no authorize_reference → middleware must
    # reject any organization-scoped subscription request.
    driver, _mock, _auth = _build(
        org_opts=None, with_org_plugin=False, authorize_reference=None
    )
    await _signup(driver, "org-disabled-test@email.com")

    r = await _upgrade(driver, plan="starter", org_id="fake-org-id")
    assert r.status != 200
    assert r.json()["code"] == "AUTHORIZE_REFERENCE_REQUIRED"
