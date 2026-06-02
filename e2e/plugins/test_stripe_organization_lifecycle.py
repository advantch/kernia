"""Organization subscription lifecycle webhooks + customer-lookup isolation.

Ports the remaining lifecycle cases of
``reference/packages/stripe/test/stripe-organization.test.ts``:

  * a ``customer.subscription.updated`` webhook for an org subscription whose
    item now points at a *different* price (resolved to the ``premium`` plan via
    its ``lookup_key``) updates the local row's ``plan`` + ``seats`` and fires
    ``onSubscriptionUpdate`` with the resolved row.
  * a ``customer.subscription.updated`` webhook carrying ``cancel_at_period_end``
    marks the row pending-cancel (``cancelAtPeriodEnd``/``cancelAt``/
    ``canceledAt``) and fires ``onSubscriptionCancel`` with the
    ``cancellationDetails``.
  * a ``customer.subscription.deleted`` webhook marks the row ``canceled`` with
    ``canceledAt``/``endedAt`` and fires ``onSubscriptionDeleted`` with the raw
    ``stripeSubscription``.
  * org customer lookup must NOT match a *user* customer that happens to carry
    the org id in its metadata — the search query is scoped by
    ``metadata["customerType"]:"organization"``.
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
    return {
        "starter": StripePlan(name="starter", price_id="price_starter"),
        "premium": StripePlan(
            name="premium", price_id="price_premium", lookup_key="lk_premium"
        ),
    }


def _build(**hook_kwargs: Any) -> tuple[ASGIDriver, MockStripe, object]:
    mock = MockStripe()
    mock.add_price("price_starter", usage_type="licensed")
    mock.add_price("price_premium", usage_type="licensed")
    sclient = StripeClient(api_key="sk_test_x", transport=mock.mock_transport())
    plugin = stripe(
        StripeOptions(
            stripe_client=sclient,
            webhook_secret=WEBHOOK_SECRET,
            create_customer_on_sign_up=False,
            plans=_plans(),
            organization=OrganizationStripeOptions(enabled=True),
            authorize_reference=lambda *_a, **_k: True,
            **hook_kwargs,
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


def _event(event_type: str, obj: dict[str, Any]) -> dict[str, Any]:
    return {"id": "evt_" + obj["id"], "type": event_type, "data": {"object": obj}}


def _item(
    price: dict[str, Any], *, quantity: int = 5, period_end: int | None = None
) -> dict[str, Any]:
    now = int(time.time())
    return {
        "id": "si_x",
        "price": price,
        "quantity": quantity,
        "current_period_start": now,
        "current_period_end": period_end or (now + 30 * 86400),
    }


# ---------------------------------------------------------------------------
# updated webhook — plan change resolved via lookup_key
# ---------------------------------------------------------------------------


async def test_org_subscription_updated_changes_plan_and_seats() -> None:
    seen: list[dict[str, Any]] = []

    async def on_update(data: dict[str, Any], *_a: Any) -> None:
        seen.append(data)

    driver, _mock, auth = _build(on_subscription_update=on_update)
    adapter = auth.context.adapter  # type: ignore[attr-defined]
    await _signup(driver, "org-update-webhook-test@email.com")
    org_id = await _create_org(
        driver, name="Update Webhook Test Org", slug="update-webhook-test-org"
    )
    await adapter.update(
        model="organization",
        where=(Where(field="id", value=org_id),),
        update={"stripeCustomerId": "cus_org_update_123"},
    )
    created = await adapter.create(
        model="subscription",
        data={
            "referenceId": org_id,
            "stripeCustomerId": "cus_org_update_123",
            "stripeSubscriptionId": "sub_org_update_123",
            "status": "active",
            "plan": "starter",
            "seats": 5,
        },
    )

    event = _event(
        "customer.subscription.updated",
        {
            "id": "sub_org_update_123",
            "customer": "cus_org_update_123",
            "status": "active",
            "items": {
                "object": "list",
                "data": [
                    _item(
                        {"id": "price_premium_123", "lookup_key": "lk_premium"},
                        quantity=10,
                    )
                ],
            },
        },
    )
    assert (await _post_webhook(driver, event)).status == 200

    updated = await adapter.find_one(
        model="subscription", where=(Where(field="id", value=created["id"]),)
    )
    assert updated is not None
    assert updated["plan"] == "premium"
    assert updated["seats"] == 10
    assert updated["status"] == "active"

    assert seen, "on_subscription_update was not called"
    assert seen[0]["subscription"]["referenceId"] == org_id
    assert seen[0]["subscription"]["plan"] == "premium"


# ---------------------------------------------------------------------------
# updated webhook — pending cancellation
# ---------------------------------------------------------------------------


async def test_org_subscription_updated_with_cancellation() -> None:
    seen: list[dict[str, Any]] = []

    async def on_cancel(data: dict[str, Any], *_a: Any) -> None:
        seen.append(data)

    driver, _mock, auth = _build(on_subscription_cancel=on_cancel)
    adapter = auth.context.adapter  # type: ignore[attr-defined]
    await _signup(driver, "org-cancel-webhook-test@email.com")
    org_id = await _create_org(
        driver, name="Cancel Webhook Test Org", slug="cancel-webhook-test-org"
    )
    await adapter.update(
        model="organization",
        where=(Where(field="id", value=org_id),),
        update={"stripeCustomerId": "cus_org_cancel_webhook_123"},
    )
    created = await adapter.create(
        model="subscription",
        data={
            "referenceId": org_id,
            "stripeCustomerId": "cus_org_cancel_webhook_123",
            "stripeSubscriptionId": "sub_org_cancel_webhook_123",
            "status": "active",
            "plan": "starter",
            "cancelAtPeriodEnd": False,
        },
    )

    now = int(time.time())
    cancel_at = now + 30 * 86400
    event = _event(
        "customer.subscription.updated",
        {
            "id": "sub_org_cancel_webhook_123",
            "customer": "cus_org_cancel_webhook_123",
            "status": "active",
            "items": {
                "object": "list",
                "data": [
                    _item(
                        {"id": "price_starter", "lookup_key": None},
                        quantity=5,
                        period_end=cancel_at,
                    )
                ],
            },
            "cancel_at_period_end": True,
            "cancel_at": cancel_at,
            "canceled_at": now,
            "cancellation_details": {
                "reason": "cancellation_requested",
                "comment": "User requested cancellation",
                "feedback": None,
            },
        },
    )
    assert (await _post_webhook(driver, event)).status == 200

    updated = await adapter.find_one(
        model="subscription", where=(Where(field="id", value=created["id"]),)
    )
    assert updated is not None
    assert updated["cancelAtPeriodEnd"] is True
    assert updated["cancelAt"] is not None
    assert updated["canceledAt"] is not None

    assert seen, "on_subscription_cancel was not called"
    assert seen[0]["subscription"]["referenceId"] == org_id
    assert seen[0]["cancellationDetails"]["reason"] == "cancellation_requested"


# ---------------------------------------------------------------------------
# deleted webhook
# ---------------------------------------------------------------------------


async def test_org_subscription_deleted() -> None:
    seen: list[dict[str, Any]] = []

    async def on_deleted(data: dict[str, Any], *_a: Any) -> None:
        seen.append(data)

    driver, _mock, auth = _build(on_subscription_deleted=on_deleted)
    adapter = auth.context.adapter  # type: ignore[attr-defined]
    await _signup(driver, "org-delete-webhook-test@email.com")
    org_id = await _create_org(
        driver, name="Delete Webhook Test Org", slug="delete-webhook-test-org"
    )
    await adapter.update(
        model="organization",
        where=(Where(field="id", value=org_id),),
        update={"stripeCustomerId": "cus_org_delete_123"},
    )
    created = await adapter.create(
        model="subscription",
        data={
            "referenceId": org_id,
            "stripeCustomerId": "cus_org_delete_123",
            "stripeSubscriptionId": "sub_org_delete_123",
            "status": "active",
            "plan": "starter",
        },
    )

    now = int(time.time())
    event = _event(
        "customer.subscription.deleted",
        {
            "id": "sub_org_delete_123",
            "customer": "cus_org_delete_123",
            "status": "canceled",
            "canceled_at": now,
            "ended_at": now,
        },
    )
    assert (await _post_webhook(driver, event)).status == 200

    deleted = await adapter.find_one(
        model="subscription", where=(Where(field="id", value=created["id"]),)
    )
    assert deleted is not None
    assert deleted["status"] == "canceled"
    assert deleted["canceledAt"] is not None
    assert deleted["endedAt"] is not None

    assert seen, "on_subscription_deleted was not called"
    assert seen[0]["subscription"]["referenceId"] == org_id
    assert seen[0]["stripeSubscription"]["id"] == "sub_org_delete_123"


# ---------------------------------------------------------------------------
# org customer lookup isolation
# ---------------------------------------------------------------------------


async def test_org_customer_lookup_excludes_user_customer() -> None:
    driver, mock, auth = _build()
    adapter = auth.context.adapter  # type: ignore[attr-defined]

    # User A signs up + upgrades, tagging their *user* customer with the org id.
    await _signup(driver, "user-a@email.com")
    user_b_id = await _signup(driver, "user-b@email.com")  # noqa: F841

    org_id = await _create_org(
        driver, name="Test Org", slug="customer-type-filter-org"
    )

    # User A (now the active session is user-b after the second sign-up); to make
    # User A active again we sign in.
    await driver.request(
        "POST",
        "/sign-in/email",
        json_body={"email": "user-a@email.com", "password": "longstrongpw"},
    )
    r = await driver.request(
        "POST",
        "/subscription/upgrade",
        json_body={"plan": "starter", "metadata": {"organizationId": org_id}},
    )
    assert r.status == 200, r.json()

    # The user customer now carries organizationId in its metadata.
    user_creates = [
        e
        for e in mock.capture_events
        if e["type"] == "customer.create"
        and (e["object"].get("metadata") or {}).get("customerType") == "user"
    ]
    assert user_creates, "expected a user customer create"
    assert user_creates[0]["object"]["metadata"]["organizationId"] == org_id

    # Switch to user B and upgrade the organization.
    await driver.request(
        "POST",
        "/sign-in/email",
        json_body={"email": "user-b@email.com", "password": "longstrongpw"},
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
    assert r.status == 200, r.json()

    # The org must have its own freshly-created customer, NOT user A's.
    updated_org = await adapter.find_one(
        model="organization", where=(Where(field="id", value=org_id),)
    )
    org_customer_id = updated_org["stripeCustomerId"]
    org_creates = [
        e
        for e in mock.capture_events
        if e["type"] == "customer.create"
        and (e["object"].get("metadata") or {}).get("customerType") == "organization"
    ]
    assert org_creates, "expected an organization customer create"
    assert org_customer_id == org_creates[0]["object"]["id"]
    assert org_customer_id != user_creates[0]["object"]["id"]
