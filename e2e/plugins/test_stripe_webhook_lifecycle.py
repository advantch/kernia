"""Subscription cancellation + schedule lifecycle propagation from webhooks.

Ports the uncovered cancellation/schedule blocks of
`reference/packages/stripe/test/webhook.test.ts`:

  * ``customer.subscription.updated`` with ``cancel_at_period_end=true`` syncs
    ``cancelAtPeriodEnd`` + ``canceledAt`` onto the local row (Billing Portal
    "cancel at period end" mode).
  * ``customer.subscription.updated`` with a future ``cancel_at`` syncs the
    ``cancelAt`` date (Dashboard/API "cancel at a specific date").
  * ``customer.subscription.deleted`` with ``ended_at`` sets ``status=canceled``
    and records ``endedAt`` (immediate cancellation) — also when an
    at-period-end subscription finally reaches its period end.
  * ``stripeScheduleId`` is synced from / cleared by the ``schedule`` field on
    update events, and always cleared on delete.
  * the ``onSubscriptionUpdate`` / ``onSubscriptionCancel`` callbacks receive
    the raw ``stripeSubscription`` and the post-update local row.

Contract note (consistent with the rest of the port): cancel/period date
columns are stored as epoch *seconds*, so assertions compare the raw second
values rather than upstream's `Date` objects.
"""

from __future__ import annotations

import hashlib
import hmac
import json as _json
import time
from typing import Any

from better_auth.auth import init
from better_auth.plugins.email_password import email_and_password
from better_auth.types.adapter import Where
from better_auth.types.init_options import (
    BetterAuthOptions,
    EmailPasswordOptions,
    RateLimitOptions,
)
from better_auth_memory_adapter import memory_adapter
from better_auth_stripe import StripeClient, StripeOptions, StripePlan, stripe
from better_auth_test_utils import ASGIDriver, MockStripe

WEBHOOK_SECRET = "whsec_test_secret"


def _plans() -> dict[str, StripePlan]:
    return {
        "starter": StripePlan(name="starter", price_id="price_starter_123"),
    }


def _build(**hook_kwargs: Any) -> tuple[ASGIDriver, MockStripe, object]:
    mock = MockStripe()
    mock.add_price("price_starter_123", usage_type="licensed")
    client = StripeClient(api_key="sk_test_x", transport=mock.mock_transport())
    plugin = stripe(
        StripeOptions(
            stripe_client=client,
            webhook_secret=WEBHOOK_SECRET,
            create_customer_on_sign_up=False,
            plans=_plans(),
            **hook_kwargs,
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
    return ASGIDriver(app=auth.router.mount()), mock, auth


def _sign(body: bytes) -> dict[str, str]:
    ts = int(time.time())
    sig = hmac.new(
        WEBHOOK_SECRET.encode("utf-8"),
        f"{ts}.".encode("ascii") + body,
        hashlib.sha256,
    ).hexdigest()
    return {
        "stripe-signature": f"t={ts},v1={sig}",
        "content-type": "application/json",
    }


async def _post_webhook(driver: ASGIDriver, event: dict[str, Any]) -> Any:
    body_bytes = _json.dumps(event).encode("utf-8")
    return await driver.request(
        "POST", "/stripe/webhook", json_body=event, headers=_sign(body_bytes)
    )


async def _seed_sub(auth: object, **extra: Any) -> dict[str, Any]:
    adapter = auth.context.adapter  # type: ignore[attr-defined]
    user = await adapter.create(
        model="user", data={"email": extra.pop("email", "wh@test.com")}
    )
    data = {
        "referenceId": user["id"],
        "status": "active",
        "plan": "starter",
        **extra,
    }
    return await adapter.create(model="subscription", data=data)


def _items(now: int, period_end: int | None = None) -> dict[str, Any]:
    return {
        "data": [
            {
                "price": {"id": "price_starter_123"},
                "quantity": 1,
                "current_period_start": now,
                "current_period_end": period_end or (now + 30 * 86400),
            }
        ]
    }


# ---------------------------------------------------------------------------
# cancel_at_period_end propagation
# ---------------------------------------------------------------------------


async def test_syncs_cancel_at_period_end_and_canceled_at() -> None:
    driver, _mock, auth = _build()
    adapter = auth.context.adapter  # type: ignore[attr-defined]
    now = int(time.time())
    sub = await _seed_sub(
        auth,
        email="cancel-period-end@test.com",
        stripeCustomerId="cus_cancel_test",
        stripeSubscriptionId="sub_cancel_period_end",
        cancelAtPeriodEnd=False,
    )

    event = {
        "id": "evt_cpe",
        "type": "customer.subscription.updated",
        "data": {
            "object": {
                "id": "sub_cancel_period_end",
                "customer": "cus_cancel_test",
                "status": "active",
                "cancel_at_period_end": True,
                "cancel_at": None,
                "canceled_at": now,
                "ended_at": None,
                "items": _items(now),
                "cancellation_details": {"reason": "cancellation_requested"},
            }
        },
    }
    assert (await _post_webhook(driver, event)).status == 200

    updated = await adapter.find_one(
        model="subscription", where=(Where(field="id", value=sub["id"]),)
    )
    assert updated["status"] == "active"
    assert updated["cancelAtPeriodEnd"] is True
    assert updated["cancelAt"] is None
    assert updated["canceledAt"] == now
    assert updated["endedAt"] is None


async def test_syncs_cancel_at_for_scheduled_date() -> None:
    driver, _mock, auth = _build()
    adapter = auth.context.adapter  # type: ignore[attr-defined]
    now = int(time.time())
    cancel_at = now + 15 * 86400
    sub = await _seed_sub(
        auth,
        email="cancel-at-date@test.com",
        stripeCustomerId="cus_cancel_at_test",
        stripeSubscriptionId="sub_cancel_at_date",
        cancelAtPeriodEnd=False,
    )

    event = {
        "id": "evt_ca",
        "type": "customer.subscription.updated",
        "data": {
            "object": {
                "id": "sub_cancel_at_date",
                "customer": "cus_cancel_at_test",
                "status": "active",
                "cancel_at_period_end": False,
                "cancel_at": cancel_at,
                "canceled_at": now,
                "ended_at": None,
                "items": _items(now),
            }
        },
    }
    assert (await _post_webhook(driver, event)).status == 200

    updated = await adapter.find_one(
        model="subscription", where=(Where(field="id", value=sub["id"]),)
    )
    assert updated["status"] == "active"
    assert updated["cancelAtPeriodEnd"] is False
    assert updated["cancelAt"] == cancel_at
    assert updated["canceledAt"] == now
    assert updated["endedAt"] is None


# ---------------------------------------------------------------------------
# immediate cancellation (subscription deleted)
# ---------------------------------------------------------------------------


async def test_sets_status_canceled_and_ended_at_on_immediate_cancel() -> None:
    driver, _mock, auth = _build()
    adapter = auth.context.adapter  # type: ignore[attr-defined]
    now = int(time.time())
    sub = await _seed_sub(
        auth,
        email="immediate-cancel@test.com",
        stripeCustomerId="cus_immediate_cancel",
        stripeSubscriptionId="sub_immediate_cancel",
    )

    event = {
        "id": "evt_imm",
        "type": "customer.subscription.deleted",
        "data": {
            "object": {
                "id": "sub_immediate_cancel",
                "customer": "cus_immediate_cancel",
                "status": "canceled",
                "cancel_at_period_end": False,
                "cancel_at": None,
                "canceled_at": now,
                "ended_at": now,
            }
        },
    }
    assert (await _post_webhook(driver, event)).status == 200

    updated = await adapter.find_one(
        model="subscription", where=(Where(field="id", value=sub["id"]),)
    )
    assert updated["status"] == "canceled"
    assert updated["endedAt"] == now


async def test_sets_ended_at_when_period_end_reached() -> None:
    driver, _mock, auth = _build()
    adapter = auth.context.adapter  # type: ignore[attr-defined]
    now = int(time.time())
    canceled_at = now - 30 * 86400
    sub = await _seed_sub(
        auth,
        email="period-end-reached@test.com",
        stripeCustomerId="cus_period_end_reached",
        stripeSubscriptionId="sub_period_end_reached",
        cancelAtPeriodEnd=True,
        canceledAt=canceled_at,
    )

    event = {
        "id": "evt_pe",
        "type": "customer.subscription.deleted",
        "data": {
            "object": {
                "id": "sub_period_end_reached",
                "customer": "cus_period_end_reached",
                "status": "canceled",
                "cancel_at_period_end": True,
                "cancel_at": None,
                "canceled_at": canceled_at,
                "ended_at": now,
            }
        },
    }
    assert (await _post_webhook(driver, event)).status == 200

    updated = await adapter.find_one(
        model="subscription", where=(Where(field="id", value=sub["id"]),)
    )
    assert updated["status"] == "canceled"
    assert updated["endedAt"] == now


# ---------------------------------------------------------------------------
# stripeScheduleId sync / clear
# ---------------------------------------------------------------------------


async def test_clears_schedule_id_when_schedule_removed() -> None:
    driver, _mock, auth = _build()
    adapter = auth.context.adapter  # type: ignore[attr-defined]
    now = int(time.time())
    sub = await _seed_sub(
        auth,
        email="schedule-clear@email.com",
        stripeCustomerId="cus_schedule_clear",
        stripeSubscriptionId="sub_schedule_clear",
        stripeScheduleId="sub_schedule_old",
    )

    event = {
        "id": "evt_sc",
        "type": "customer.subscription.updated",
        "data": {
            "object": {
                "id": "sub_schedule_clear",
                "customer": "cus_schedule_clear",
                "status": "active",
                "schedule": None,
                "items": _items(now),
            }
        },
    }
    assert (await _post_webhook(driver, event)).status == 200

    updated = await adapter.find_one(
        model="subscription", where=(Where(field="id", value=sub["id"]),)
    )
    assert updated["stripeScheduleId"] is None


async def test_clears_schedule_id_on_subscription_deleted() -> None:
    driver, _mock, auth = _build()
    adapter = auth.context.adapter  # type: ignore[attr-defined]
    now = int(time.time())
    sub = await _seed_sub(
        auth,
        email="schedule-del@email.com",
        stripeCustomerId="cus_schedule_del",
        stripeSubscriptionId="sub_schedule_del",
        stripeScheduleId="sub_schedule_will_be_cleared",
    )

    event = {
        "id": "evt_scd",
        "type": "customer.subscription.deleted",
        "data": {
            "object": {
                "id": "sub_schedule_del",
                "customer": "cus_schedule_del",
                "status": "canceled",
                "canceled_at": now,
                "ended_at": now,
            }
        },
    }
    assert (await _post_webhook(driver, event)).status == 200

    updated = await adapter.find_one(
        model="subscription", where=(Where(field="id", value=sub["id"]),)
    )
    assert updated["stripeScheduleId"] is None


# ---------------------------------------------------------------------------
# callback payload symmetry
# ---------------------------------------------------------------------------


async def test_passes_stripe_subscription_to_on_subscription_update() -> None:
    captured: list[dict[str, Any]] = []

    async def on_update(data: dict[str, Any]) -> None:
        captured.append(data)

    driver, _mock, auth = _build(on_subscription_update=on_update)
    now = int(time.time())
    await _seed_sub(
        auth,
        email="9321@test.com",
        stripeCustomerId="cus_9321",
        stripeSubscriptionId="sub_9321",
    )

    event = {
        "id": "evt_upd_cb",
        "type": "customer.subscription.updated",
        "data": {
            "object": {
                "id": "sub_9321",
                "customer": "cus_9321",
                "status": "active",
                "cancel_at_period_end": True,
                "cancel_at": now + 15 * 86400,
                "canceled_at": now,
                "ended_at": None,
                "items": _items(now),
            }
        },
    }
    assert (await _post_webhook(driver, event)).status == 200

    assert captured, "on_subscription_update was not called"
    assert isinstance(captured[0].get("stripeSubscription"), dict)
    assert captured[0]["stripeSubscription"]["id"] == "sub_9321"


async def test_passes_post_update_row_to_on_subscription_cancel() -> None:
    captured: list[dict[str, Any]] = []

    async def on_cancel(data: dict[str, Any]) -> None:
        captured.append(data)

    driver, _mock, auth = _build(on_subscription_cancel=on_cancel)
    now = int(time.time())
    cancel_at = now + 15 * 86400
    await _seed_sub(
        auth,
        email="cancel-timing@test.com",
        stripeCustomerId="cus_cancel_timing",
        stripeSubscriptionId="sub_cancel_timing",
        cancelAtPeriodEnd=False,
    )

    event = {
        "id": "evt_cancel_cb",
        "type": "customer.subscription.updated",
        "data": {
            "object": {
                "id": "sub_cancel_timing",
                "customer": "cus_cancel_timing",
                "status": "active",
                "cancel_at_period_end": True,
                "cancel_at": cancel_at,
                "canceled_at": now,
                "ended_at": None,
                "items": _items(now),
                "cancellation_details": {"reason": "cancellation_requested"},
            }
        },
    }
    assert (await _post_webhook(driver, event)).status == 200

    assert len(captured) == 1
    row = captured[0]["subscription"]
    assert row["cancelAtPeriodEnd"] is True
    assert row["cancelAt"] == cancel_at
    assert row["canceledAt"] == now
