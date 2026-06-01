"""Seat-aware plan upgrades — swapping seat line items on the active sub.

Ports the `describe("portal upgrade with seat items")` block of
`reference/packages/stripe/test/seat-based-billing.test.ts`. When an
organization on a seat plan upgrades to another seat plan, the active Stripe
subscription's items must be swapped in place: the base item moves to the new
base price (keeping its item id) and the seat item moves to the new seat price
(keeping its id + quantity), applied with the plan's ``proration_behavior``.

Divergence note: upstream routes single-item (seat-unchanged) changes through
the Billing Portal and falls back to ``subscriptions.update`` only for the
multi-item seat-price-change case. The Python port applies *all* immediate
upgrades via ``subscriptions.update`` (see the divergence note in
``test_stripe_schedule.py``); these tests therefore assert the item-swap
payload on ``subscriptions.update`` for every case, which is the Python
contract. The item-swap semantics asserted (correct base/seat price mapping,
preserved ids, no duplicate items) are identical to upstream.
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


def _build(plans: dict[str, StripePlan]) -> tuple[ASGIDriver, MockStripe, object]:
    mock = MockStripe()
    client = StripeClient(api_key="sk_test_x", transport=mock.mock_transport())
    plugin = stripe(
        StripeOptions(
            stripe_client=client,
            webhook_secret=WEBHOOK_SECRET,
            create_customer_on_sign_up=False,
            plans=plans,
            organization=OrganizationStripeOptions(enabled=True),
            authorize_reference=lambda *_a, **_k: True,
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


async def _seed_active_org_sub(
    auth: object,
    mock: MockStripe,
    *,
    org_id: str,
    customer: str,
    sub_id: str,
    plan: str,
    items: list[dict[str, Any]],
    seats: int,
) -> None:
    adapter = auth.context.adapter  # type: ignore[attr-defined]
    await adapter.update(
        model="organization",
        where=(Where(field="id", value=org_id),),
        update={"stripeCustomerId": customer},
    )
    await adapter.create(
        model="subscription",
        data={
            "referenceId": org_id,
            "stripeCustomerId": customer,
            "stripeSubscriptionId": sub_id,
            "status": "active",
            "plan": plan,
            "seats": seats,
        },
    )
    mock.add_subscription(sub_id, customer=customer, items=items)


async def _upgrade(driver: ASGIDriver, *, plan: str, org_id: str) -> Any:
    return await driver.request(
        "POST",
        "/subscription/upgrade",
        json_body={"plan": plan, "customerType": "organization", "referenceId": org_id},
    )


def _update_event(mock: MockStripe) -> dict[str, Any]:
    return next(e for e in mock.capture_events if e["type"] == "subscription.update")


def _items_by_id(event: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Map item id -> {price, quantity} from a reflected subscription.update."""
    out: dict[str, dict[str, Any]] = {}
    for it in (event["object"].get("items") or {}).get("data") or []:
        out[it.get("id")] = {
            "price": (it.get("price") or {}).get("id"),
            "quantity": it.get("quantity"),
        }
    return out


# ---------------------------------------------------------------------------
# seat price change → swap both base and seat items
# ---------------------------------------------------------------------------


def _two_plan_options(proration: str = "create_prorations") -> dict[str, StripePlan]:
    return {
        "team": StripePlan(
            name="team",
            price_id="price_team_base",
            seat_price_id="price_team_seat",
            proration_behavior=proration,
        ),
        "enterprise": StripePlan(
            name="enterprise",
            price_id="price_enterprise_base",
            seat_price_id="price_enterprise_seat",
            proration_behavior=proration,
        ),
    }


async def test_swaps_seat_item_for_different_seat_pricing() -> None:
    driver, mock, auth = _build(_two_plan_options())
    await _signup(driver, "portal-seat@test.com")
    org_id = await _create_org(driver, name="Portal Seat Org", slug="portal-seat-org")
    await _seed_active_org_sub(
        auth,
        mock,
        org_id=org_id,
        customer="cus_portal_seat",
        sub_id="sub_team",
        plan="team",
        items=[
            {"id": "si_base", "price": "price_team_base", "quantity": 1},
            {"id": "si_seat", "price": "price_team_seat", "quantity": 2},
        ],
        seats=2,
    )

    r = await _upgrade(driver, plan="enterprise", org_id=org_id)
    assert r.status == 200, r.json()

    # No billing-portal session; the seat price change goes through update().
    assert not [
        e for e in mock.capture_events if e["type"] == "billing_portal.session.create"
    ]
    event = _update_event(mock)
    assert event["object"]["id"] == "sub_team"
    items = _items_by_id(event)
    assert items["si_base"]["price"] == "price_enterprise_base"
    assert items["si_seat"]["price"] == "price_enterprise_seat"
    assert items["si_seat"]["quantity"] is not None
    assert event["params"]["proration_behavior"] == "create_prorations"


async def test_uses_custom_proration_behavior_from_plan() -> None:
    driver, mock, auth = _build(_two_plan_options(proration="always_invoice"))
    await _signup(driver, "proration-test@test.com")
    org_id = await _create_org(driver, name="Proration Org", slug="proration-org")
    await _seed_active_org_sub(
        auth,
        mock,
        org_id=org_id,
        customer="cus_proration",
        sub_id="sub_proration",
        plan="team",
        items=[
            {"id": "si_base", "price": "price_team_base", "quantity": 1},
            {"id": "si_seat", "price": "price_team_seat", "quantity": 2},
        ],
        seats=2,
    )

    r = await _upgrade(driver, plan="enterprise", org_id=org_id)
    assert r.status == 200, r.json()
    assert _update_event(mock)["params"]["proration_behavior"] == "always_invoice"


# ---------------------------------------------------------------------------
# seat pricing unchanged (shared seat price) → only the base item changes
# ---------------------------------------------------------------------------


async def test_keeps_shared_seat_item_when_pricing_unchanged() -> None:
    plans = {
        "basic": StripePlan(
            name="basic", price_id="price_basic_base", seat_price_id="price_shared_seat"
        ),
        "pro": StripePlan(
            name="pro", price_id="price_pro_base", seat_price_id="price_shared_seat"
        ),
    }
    driver, mock, auth = _build(plans)
    await _signup(driver, "same-seat@test.com")
    org_id = await _create_org(driver, name="Same Seat Org", slug="same-seat-org")
    await _seed_active_org_sub(
        auth,
        mock,
        org_id=org_id,
        customer="cus_same_seat",
        sub_id="sub_basic",
        plan="basic",
        items=[
            {"id": "si_base", "price": "price_basic_base", "quantity": 1},
            {"id": "si_seat", "price": "price_shared_seat", "quantity": 1},
        ],
        seats=1,
    )

    r = await _upgrade(driver, plan="pro", org_id=org_id)
    assert r.status == 200, r.json()

    event = _update_event(mock)
    items = _items_by_id(event)
    # Base item moves to the new base price; the shared seat price is unchanged.
    assert items["si_base"]["price"] == "price_pro_base"
    assert items["si_seat"]["price"] == "price_shared_seat"


# ---------------------------------------------------------------------------
# seat-only plans (single item where base price IS the seat price)
# ---------------------------------------------------------------------------


async def test_no_duplicate_item_between_seat_only_plans() -> None:
    plans = {
        "starter": StripePlan(
            name="starter", price_id="price_starter", seat_price_id="price_starter"
        ),
        "growth": StripePlan(
            name="growth", price_id="price_growth", seat_price_id="price_growth"
        ),
    }
    driver, mock, auth = _build(plans)
    await _signup(driver, "seat-only-upgrade@test.com")
    org_id = await _create_org(
        driver, name="Seat Only Upgrade Org", slug="seat-only-upgrade-org"
    )
    await _seed_active_org_sub(
        auth,
        mock,
        org_id=org_id,
        customer="cus_seat_only_upgrade",
        sub_id="sub_starter",
        plan="starter",
        items=[{"id": "si_only", "price": "price_starter", "quantity": 2}],
        seats=2,
    )

    r = await _upgrade(driver, plan="growth", org_id=org_id)
    assert r.status == 200, r.json()

    event = _update_event(mock)
    assert event["object"]["id"] == "sub_starter"
    items = (event["object"].get("items") or {}).get("data") or []
    # Exactly one item — the single seat-only item swapped to the new price.
    assert len(items) == 1
    assert items[0]["id"] == "si_only"
    assert items[0]["price"]["id"] == "price_growth"
    assert items[0]["quantity"] is not None
