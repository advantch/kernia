"""Stripe seat-sync: the seat line-item quantity tracks org membership.

Ports the `describe("seat sync on member changes")` and
`describe("seat sync on member removal")` blocks of
`reference/packages/stripe/test/seat-based-billing.test.ts`.

Wires the organization plugin + stripe plugin in a single auth instance with an
organization integration enabled and a seat plan (`seat_price_id` set), seeds an
active subscription whose Stripe items include a dedicated seat item, then drives
the member-add (accept-invitation) / member-remove paths through the org
endpoints. The seat-sync subscriber must call `subscriptions.update` with the
seat item's id and the new member count, honouring the plan's proration
behaviour. Mirrors upstream's `syncSeatsAfterMemberChange`.
"""

from __future__ import annotations

import asyncio

import pytest
from kernia.auth import init
from kernia.plugins import email_and_password
from kernia.plugins.organization import organization
from kernia.types.adapter import Where
from kernia.types.init_options import KerniaOptions
from kernia_memory_adapter import memory_adapter
from kernia_stripe import stripe
from kernia_stripe.client import StripeClient
from kernia_stripe.schema import (
    OrganizationStripeOptions,
    StripeOptions,
    StripePlan,
)
from kernia_test_utils import ASGIDriver, MockStripe


def _seat_plans(proration_behavior: str = "create_prorations") -> dict[str, StripePlan]:
    return {
        "team": StripePlan(
            name="team",
            price_id="price_team_base",
            seat_price_id="price_team_seat",
            proration_behavior=proration_behavior,
        ),
        "enterprise": StripePlan(
            name="enterprise",
            price_id="price_enterprise_base",
            seat_price_id="price_enterprise_seat",
            proration_behavior=proration_behavior,
        ),
    }


async def _build_driver(
    proration_behavior: str = "create_prorations",
) -> tuple[ASGIDriver, MockStripe, object]:
    mock = MockStripe()
    sclient = StripeClient(api_key="sk_test", transport=mock.mock_transport())
    options = StripeOptions(
        stripe_client=sclient,
        webhook_secret="whsec_test",
        create_customer_on_sign_up=False,
        plans=_seat_plans(proration_behavior),
        organization=OrganizationStripeOptions(enabled=True),
        authorize_reference=lambda *_a, **_k: True,
    )
    auth = init(
        KerniaOptions(
            database=memory_adapter(),
            secret="test-secret",
            plugins=[email_and_password(), organization(), stripe(options)],
        )
    )
    # Drain plugin-init fire-and-forget tasks so subscribers are registered.
    await asyncio.sleep(0)
    await asyncio.sleep(0)
    return ASGIDriver(app=auth.router.mount()), mock, auth


async def _sign_up(driver: ASGIDriver, email: str, password: str = "correcthorse") -> dict:
    r = await driver.request(
        "POST", "/sign-up/email", json_body={"email": email, "password": password}
    )
    assert r.status == 200, r.json()
    return r.json()["user"]


async def _create_org_with_active_sub(
    auth, mock: MockStripe, owner_id: str, *, sub_id: str, seat_qty: int
) -> str:
    """Create an org owned by `owner_id` plus an active seat subscription.

    Seeds both the local subscription row and the Stripe-side subscription (with
    a base item + a dedicated seat item) so `subscriptions.retrieve` finds the
    seat item by `price.id`.
    """
    org = await auth.context.adapter.create(
        model="organization",
        data={"name": "Acme", "slug": "acme", "metadata": {}},
    )
    await auth.context.adapter.create(
        model="member",
        data={
            "organizationId": org["id"],
            "userId": owner_id,
            "role": "owner",
            "createdAt": 0,
        },
    )
    await auth.context.adapter.update(
        model="organization",
        where=(Where(field="id", value=org["id"]),),
        update={"stripeCustomerId": "cus_sync_seat"},
    )
    await auth.context.adapter.create(
        model="subscription",
        data={
            "plan": "team",
            "referenceId": org["id"],
            "stripeCustomerId": "cus_sync_seat",
            "stripeSubscriptionId": sub_id,
            "status": "active",
            "seats": seat_qty,
        },
    )
    mock.add_subscription(
        sub_id,
        customer="cus_sync_seat",
        items=[
            {"id": "si_base", "price": "price_team_base", "quantity": 1},
            {"id": "si_seat", "price": "price_team_seat", "quantity": seat_qty},
        ],
    )
    return org["id"]


async def _set_active_org(auth, user_id: str, org_id: str) -> None:
    sess_row = await auth.context.adapter.find_one(
        model="session", where=(Where(field="userId", value=user_id),)
    )
    await auth.context.adapter.update(
        model="session",
        where=(Where(field="id", value=sess_row["id"]),),
        update={"activeOrganizationId": org_id},
    )


def _seat_updates(mock: MockStripe) -> list[dict]:
    return [e for e in mock.capture_events if e["type"] == "subscription.update"]


@pytest.mark.asyncio
async def test_seat_sync_increments_on_invite_accept() -> None:
    driver, mock, auth = await _build_driver()
    owner = await _sign_up(driver, "owner@example.com")
    org_id = await _create_org_with_active_sub(
        auth, mock, owner["id"], sub_id="sub_seat_sync", seat_qty=1
    )
    await _set_active_org(auth, owner["id"], org_id)

    r = await driver.request(
        "POST",
        "/organization/invite-member",
        json_body={
            "organizationId": org_id,
            "email": "newbie@example.com",
            "role": "member",
        },
    )
    assert r.status == 200, r.json()
    invitation_id = r.json()["invitation"]["id"]

    driver2 = ASGIDriver(app=auth.router.mount())
    await _sign_up(driver2, "newbie@example.com")
    r = await driver2.request(
        "POST",
        "/organization/accept-invitation",
        json_body={"invitationId": invitation_id},
    )
    assert r.status == 200, r.json()

    updates = _seat_updates(mock)
    assert updates, "expected at least one Stripe subscription.update event"
    p = updates[0]["params"]
    assert p["proration_behavior"] == "create_prorations"
    # Updates the existing seat item by id, with the new member count.
    assert p["items[0][id]"] == "si_seat"
    assert p["items[0][quantity]"] == "2"

    row = await auth.context.adapter.find_one(
        model="subscription",
        where=(Where(field="stripeSubscriptionId", value="sub_seat_sync"),),
    )
    assert row["seats"] == 2


@pytest.mark.asyncio
async def test_seat_sync_decrements_on_remove_member() -> None:
    driver, mock, auth = await _build_driver()
    owner = await _sign_up(driver, "owner@example.com")
    org_id = await _create_org_with_active_sub(
        auth, mock, owner["id"], sub_id="sub_seat_remove", seat_qty=2
    )
    await _set_active_org(auth, owner["id"], org_id)

    other = await auth.context.adapter.create(
        model="user",
        data={"email": "x@example.com", "emailVerified": True},
    )
    member_row = await auth.context.adapter.create(
        model="member",
        data={
            "organizationId": org_id,
            "userId": other["id"],
            "role": "member",
            "createdAt": 0,
        },
    )

    r = await driver.request(
        "POST",
        "/organization/remove-member",
        json_body={"organizationId": org_id, "memberIdOrEmail": member_row["id"]},
    )
    assert r.status == 200, r.json()

    updates = _seat_updates(mock)
    assert updates, "expected at least one Stripe subscription.update event"
    p = updates[0]["params"]
    assert p["proration_behavior"] == "create_prorations"
    # Owner only remains → seat item quantity = 1.
    assert p["items[0][id]"] == "si_seat"
    assert p["items[0][quantity]"] == "1"


@pytest.mark.asyncio
async def test_seat_sync_uses_custom_proration_behavior_on_removal() -> None:
    driver, mock, auth = await _build_driver(proration_behavior="none")
    owner = await _sign_up(driver, "owner@example.com")
    org_id = await _create_org_with_active_sub(
        auth, mock, owner["id"], sub_id="sub_seat_remove_proration", seat_qty=2
    )
    await _set_active_org(auth, owner["id"], org_id)

    other = await auth.context.adapter.create(
        model="user",
        data={"email": "y@example.com", "emailVerified": True},
    )
    member_row = await auth.context.adapter.create(
        model="member",
        data={
            "organizationId": org_id,
            "userId": other["id"],
            "role": "member",
            "createdAt": 0,
        },
    )

    r = await driver.request(
        "POST",
        "/organization/remove-member",
        json_body={"organizationId": org_id, "memberIdOrEmail": member_row["id"]},
    )
    assert r.status == 200, r.json()

    updates = _seat_updates(mock)
    assert updates, "expected at least one Stripe subscription.update event"
    assert updates[0]["params"]["proration_behavior"] == "none"


@pytest.mark.asyncio
async def test_seat_sync_no_op_when_organization_integration_disabled() -> None:
    """No listener registers when the organization integration is absent."""
    mock = MockStripe()
    sclient = StripeClient(api_key="sk_test", transport=mock.mock_transport())
    options = StripeOptions(
        stripe_client=sclient,
        webhook_secret="whsec_test",
        plans={"pro": StripePlan(name="pro", price_id="price_pro")},
        # No organization integration → seat-sync must not register.
    )
    auth = init(
        KerniaOptions(
            database=memory_adapter(),
            secret="s",
            plugins=[email_and_password(), organization(), stripe(options)],
        )
    )
    await asyncio.sleep(0)
    await asyncio.sleep(0)
    driver = ASGIDriver(app=auth.router.mount())
    owner = await _sign_up(driver, "owner@example.com")
    org = await auth.context.adapter.create(
        model="organization", data={"name": "x", "slug": "x", "metadata": {}}
    )
    await auth.context.adapter.create(
        model="member",
        data={
            "organizationId": org["id"],
            "userId": owner["id"],
            "role": "owner",
            "createdAt": 0,
        },
    )

    from kernia.events import MemberEvent, get_bus

    await get_bus(auth.context).emit(
        "organization.member.added",
        MemberEvent(organization_id=org["id"], user_id="someone", role="member", action="added"),
    )
    assert all(e["type"] != "subscription.update" for e in mock.capture_events)
