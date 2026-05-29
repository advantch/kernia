"""Seat-based billing — auto-managed seat line items at checkout.

Ports the `describe("checkout with auto-managed seats")`,
`describe("checkout with additional line items")`, and
`describe("checkout when priceId equals seatPriceId")` blocks of
`reference/packages/stripe/test/seat-based-billing.test.ts`.

When a plan declares `seat_price_id` and the subscription is for an
organization, seats are auto-managed: the Checkout session carries a base price
line item (`quantity: 1`) plus a per-seat line item priced at `seat_price_id`
with `quantity == organization member count`. Plan-declared `line_items`
(add-ons / metered) are appended verbatim. When `price_id == seat_price_id`
(seat-only plan) the base item is dropped so the seat price is not duplicated.
"""

from __future__ import annotations

from typing import Any

from better_auth.auth import init
from better_auth.plugins.email_password import email_and_password
from better_auth.plugins.organization import organization
from better_auth.types.init_options import (
    BetterAuthOptions,
    EmailPasswordOptions,
    RateLimitOptions,
)
from better_auth_memory_adapter import memory_adapter
from better_auth_stripe import StripeClient, StripeOptions, StripePlan, stripe
from better_auth_stripe.schema import OrganizationStripeOptions
from better_auth_test_utils import ASGIDriver, MockStripe

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
        BetterAuthOptions(
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


async def _add_member(auth: object, *, email: str, org_id: str) -> None:
    import time

    adapter = auth.context.adapter  # type: ignore[attr-defined]
    member_user = await adapter.create(model="user", data={"email": email, "name": email})
    await adapter.create(
        model="member",
        data={
            "userId": member_user["id"],
            "organizationId": org_id,
            "role": "member",
            "createdAt": int(time.time()),
        },
    )


async def _upgrade_org(driver: ASGIDriver, *, plan: str, org_id: str) -> dict:
    return await driver.request(
        "POST",
        "/subscription/upgrade",
        json_body={
            "plan": plan,
            "customerType": "organization",
            "referenceId": org_id,
        },
    )


def _checkout_line_items(mock: MockStripe) -> list[dict[str, Any]]:
    ev = next(e for e in mock.capture_events if e["type"] == "checkout.session.create")
    return ev["object"]["line_items"]


def _seat_plan() -> dict[str, StripePlan]:
    return {
        "team": StripePlan(
            name="team", price_id="price_team_base", seat_price_id="price_team_seat"
        )
    }


# ---------------------------------------------------------------------------
# auto-managed seats
# ---------------------------------------------------------------------------


async def test_checkout_has_base_and_seat_line_items() -> None:
    driver, mock, _auth = _build(_seat_plan())
    await _signup(driver, "seat-test@email.com")
    org_id = await _create_org(driver, name="Seat Test Org", slug="seat-test-org")
    r = await _upgrade_org(driver, plan="team", org_id=org_id)
    assert r.status == 200, r.json()
    items = _checkout_line_items(mock)
    assert items[0] == {"price": "price_team_base", "quantity": "1"}
    assert items[1]["price"] == "price_team_seat"
    assert items[1]["quantity"] is not None


async def test_seat_quantity_tracks_member_count() -> None:
    driver, mock, auth = _build(_seat_plan())
    await _signup(driver, "seat-count@email.com")
    org_id = await _create_org(driver, name="Seat Count Org", slug="seat-count-org")
    # Owner is member #1; add two more → 3.
    await _add_member(auth, email="member2@seat.com", org_id=org_id)
    await _add_member(auth, email="member3@seat.com", org_id=org_id)
    r = await _upgrade_org(driver, plan="team", org_id=org_id)
    assert r.status == 200, r.json()
    items = _checkout_line_items(mock)
    assert items[1] == {"price": "price_team_seat", "quantity": "3"}


# ---------------------------------------------------------------------------
# additional line items
# ---------------------------------------------------------------------------


async def test_includes_additional_line_items() -> None:
    plans = {
        "pro": StripePlan(
            name="pro",
            price_id="price_pro_base",
            seat_price_id="price_pro_seat",
            line_items=(
                {"price": "price_meter_api"},
                {"price": "price_meter_email"},
            ),
        )
    }
    driver, mock, _auth = _build(plans)
    await _signup(driver, "meter-test@email.com")
    org_id = await _create_org(driver, name="Meter Test Org", slug="meter-test-org")
    r = await _upgrade_org(driver, plan="pro", org_id=org_id)
    assert r.status == 200, r.json()
    items = _checkout_line_items(mock)
    assert len(items) == 4  # base + seat + 2 line items
    assert items[0] == {"price": "price_pro_base", "quantity": "1"}
    assert items[1]["price"] == "price_pro_seat"
    assert items[2] == {"price": "price_meter_api"}
    assert items[3] == {"price": "price_meter_email"}


async def test_no_extra_line_items_when_plan_has_none() -> None:
    plans = {
        "basic": StripePlan(
            name="basic", price_id="price_basic_base", seat_price_id="price_basic_seat"
        )
    }
    driver, mock, _auth = _build(plans)
    await _signup(driver, "no-meter@email.com")
    org_id = await _create_org(driver, name="No Meter Org", slug="no-meter-org")
    r = await _upgrade_org(driver, plan="basic", org_id=org_id)
    assert r.status == 200, r.json()
    items = _checkout_line_items(mock)
    assert len(items) == 2  # base + seat only


# ---------------------------------------------------------------------------
# priceId == seatPriceId
# ---------------------------------------------------------------------------


async def test_seat_only_plan_does_not_duplicate_base_price() -> None:
    plans = {
        "starter": StripePlan(
            name="starter",
            price_id="price_same",
            seat_price_id="price_same",
            line_items=({"price": "price_meter_api"},),
        )
    }
    driver, mock, _auth = _build(plans)
    await _signup(driver, "seat-only@email.com")
    org_id = await _create_org(driver, name="Seat Only Org", slug="seat-only-org")
    r = await _upgrade_org(driver, plan="starter", org_id=org_id)
    assert r.status == 200, r.json()
    items = _checkout_line_items(mock)
    assert len(items) == 2  # seat + 1 meter, no duplicate base
    assert items[0]["price"] == "price_same"
    assert items[0]["quantity"] is not None
    assert items[1] == {"price": "price_meter_api"}
