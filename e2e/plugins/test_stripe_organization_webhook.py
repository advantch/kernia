"""Organization webhook handling + org subscription error paths.

Ports the remaining `describe("stripe - organization customer")` cases of
`reference/packages/stripe/test/stripe-organization.test.ts`:

  * a ``customer.subscription.created`` webhook for a subscription created
    directly in the Stripe Dashboard creates a local subscription row whose
    ``referenceId`` resolves to the organization (via the org's
    ``stripeCustomerId``), carrying the item ``quantity`` as ``seats``.
  * the ``onSubscriptionCreated`` callback receives the local row, the raw
    ``stripeSubscription`` and the resolved plan.
  * cross-organization operations are rejected when ``authorizeReference``
    returns ``False`` (``UNAUTHORIZED``).
  * a Stripe ``customers.create`` failure or a throwing
    ``getCustomerCreateParams`` surfaces as ``UNABLE_TO_CREATE_CUSTOMER``.
"""

from __future__ import annotations

import hashlib
import hmac
import json as _json
import time
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
    return {"starter": StripePlan(name="starter", price_id="price_starter")}


def _build(
    *,
    org_opts: OrganizationStripeOptions | None = None,
    authorize_reference: Any = lambda *_a, **_k: True,
    client: StripeClient | None = None,
    on_subscription_created: Any = None,
) -> tuple[ASGIDriver, MockStripe, object]:
    mock = MockStripe()
    mock.add_price("price_starter", usage_type="licensed")
    sclient = client or StripeClient(
        api_key="sk_test_x", transport=mock.mock_transport()
    )
    plugin = stripe(
        StripeOptions(
            stripe_client=sclient,
            webhook_secret=WEBHOOK_SECRET,
            create_customer_on_sign_up=False,
            plans=_plans(),
            organization=org_opts or OrganizationStripeOptions(enabled=True),
            authorize_reference=authorize_reference,
            on_subscription_created=on_subscription_created,
        )
    )
    auth = init(
        KerniaOptions(
            database=memory_adapter(),
            secret="stripe-secret",
            email_and_password=EmailPasswordOptions(enabled=True),
            plugins=[email_and_password(), organization(), plugin],
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


def _sign(body: bytes) -> dict[str, str]:
    ts = int(time.time())
    sig = hmac.new(
        WEBHOOK_SECRET.encode("utf-8"),
        f"{ts}.".encode("ascii") + body,
        hashlib.sha256,
    ).hexdigest()
    return {"stripe-signature": f"t={ts},v1={sig}", "content-type": "application/json"}


async def _post_webhook(driver: ASGIDriver, event: dict[str, Any]) -> Any:
    body = _json.dumps(event).encode("utf-8")
    return await driver.request(
        "POST", "/stripe/webhook", json_body=event, headers=_sign(body)
    )


def _created_event(sub_id: str, customer: str, *, quantity: int = 5) -> dict[str, Any]:
    now = int(time.time())
    return {
        "id": "evt_" + sub_id,
        "type": "customer.subscription.created",
        "data": {
            "object": {
                "id": sub_id,
                "customer": customer,
                "status": "active",
                "items": {
                    "object": "list",
                    "data": [
                        {
                            "id": "si_x",
                            "price": {"id": "price_starter", "lookup_key": None},
                            "quantity": quantity,
                            "current_period_start": now,
                            "current_period_end": now + 30 * 86400,
                        }
                    ],
                },
            }
        },
    }


# ---------------------------------------------------------------------------
# dashboard-created subscription webhook
# ---------------------------------------------------------------------------


async def test_webhook_creates_org_subscription_from_dashboard() -> None:
    driver, _mock, auth = _build()
    adapter = auth.context.adapter  # type: ignore[attr-defined]
    await _signup(driver, "org-webhook-test@email.com")
    org_id = await _create_org(driver, name="Webhook Test Org", slug="webhook-org")
    await adapter.update(
        model="organization",
        where=(Where(field="id", value=org_id),),
        update={"stripeCustomerId": "cus_org_webhook_123"},
    )

    event = _created_event("sub_org_webhook_123", "cus_org_webhook_123", quantity=5)
    assert (await _post_webhook(driver, event)).status == 200

    sub = await adapter.find_one(
        model="subscription",
        where=(Where(field="stripeSubscriptionId", value="sub_org_webhook_123"),),
    )
    assert sub is not None
    assert sub["referenceId"] == org_id
    assert sub["stripeCustomerId"] == "cus_org_webhook_123"
    assert sub["status"] == "active"
    assert sub["plan"] == "starter"
    assert sub["seats"] == 5


async def test_calls_on_subscription_created_for_org_dashboard() -> None:
    seen: list[dict[str, Any]] = []

    async def on_created(data: dict[str, Any], *_a: Any) -> None:
        seen.append(data)

    driver, _mock, auth = _build(on_subscription_created=on_created)
    adapter = auth.context.adapter  # type: ignore[attr-defined]
    await _signup(driver, "org-created-callback@email.com")
    org_id = await _create_org(driver, name="Created CB Org", slug="created-cb-org")
    await adapter.update(
        model="organization",
        where=(Where(field="id", value=org_id),),
        update={"stripeCustomerId": "cus_org_created_callback_123"},
    )

    event = _created_event(
        "sub_org_created_callback_123", "cus_org_created_callback_123"
    )
    assert (await _post_webhook(driver, event)).status == 200

    assert seen, "on_subscription_created was not called"
    payload = seen[0]
    assert payload["subscription"]["referenceId"] == org_id
    assert payload["subscription"]["plan"] == "starter"
    assert payload["stripeSubscription"]["id"] == "sub_org_created_callback_123"
    assert payload["plan"].name == "starter"


# ---------------------------------------------------------------------------
# cross-organization isolation
# ---------------------------------------------------------------------------


async def test_cross_org_cancel_is_unauthorized() -> None:
    other_org_id_box: dict[str, str] = {"id": ""}

    def authorize(payload: dict[str, Any], *_a: Any) -> bool:
        return payload.get("referenceId") != other_org_id_box["id"]

    driver, _mock, auth = _build(authorize_reference=authorize)
    adapter = auth.context.adapter  # type: ignore[attr-defined]
    await _signup(driver, "cross-org-test@email.com")
    await _create_org(driver, name="User Org", slug="user-org")

    other_org = await adapter.create(
        model="organization",
        data={"name": "Other Org", "slug": "other-org", "metadata": {}},
    )
    other_org_id_box["id"] = other_org["id"]
    await adapter.update(
        model="organization",
        where=(Where(field="id", value=other_org["id"]),),
        update={"stripeCustomerId": "cus_other_org"},
    )
    await adapter.create(
        model="subscription",
        data={
            "referenceId": other_org["id"],
            "stripeCustomerId": "cus_other_org",
            "stripeSubscriptionId": "sub_other_org",
            "status": "active",
            "plan": "starter",
        },
    )

    r = await driver.request(
        "POST",
        "/subscription/cancel",
        json_body={
            "customerType": "organization",
            "referenceId": other_org["id"],
            "returnUrl": "/dashboard",
        },
    )
    assert r.status != 200
    assert r.json()["code"] == "UNAUTHORIZED"


# ---------------------------------------------------------------------------
# customer creation error paths
# ---------------------------------------------------------------------------


async def test_org_customer_creation_failure_surfaces_error() -> None:
    mock = MockStripe()
    mock.add_price("price_starter", usage_type="licensed")
    client = StripeClient(api_key="sk_test_x", transport=mock.mock_transport())

    async def _raise(**_kw: Any) -> dict[str, Any]:
        raise RuntimeError("Stripe API error")

    client.create_customer = _raise  # type: ignore[method-assign]

    driver, _mock, _auth = _build(client=client)
    await _signup(driver, "stripe-fail-test@email.com")
    org_id = await _create_org(driver, name="Stripe Fail Org", slug="stripe-fail-org")

    r = await driver.request(
        "POST",
        "/subscription/upgrade",
        json_body={
            "plan": "starter",
            "customerType": "organization",
            "referenceId": org_id,
        },
    )
    assert r.status != 200
    assert r.json()["code"] == "UNABLE_TO_CREATE_CUSTOMER"


async def test_get_customer_create_params_throwing_surfaces_error() -> None:
    async def get_params(*_a: Any, **_k: Any) -> dict[str, Any]:
        raise RuntimeError("Callback error")

    driver, _mock, _auth = _build(
        org_opts=OrganizationStripeOptions(
            enabled=True, get_customer_create_params=get_params
        )
    )
    await _signup(driver, "callback-throw-test@email.com")
    org_id = await _create_org(
        driver, name="Callback Throw Org", slug="callback-throw-org"
    )

    r = await driver.request(
        "POST",
        "/subscription/upgrade",
        json_body={
            "plan": "starter",
            "customerType": "organization",
            "referenceId": org_id,
        },
    )
    assert r.status != 200
    assert r.json()["code"] == "UNABLE_TO_CREATE_CUSTOMER"
