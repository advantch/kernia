"""Stripe seat-sync: subscription quantity tracks org membership.

Wires the organization plugin + stripe plugin in a single auth instance, creates
an active seat-mode subscription against MockStripe, then exercises the
member-add / member-remove paths through the organization endpoints. The
seat-sync event subscriber must call MockStripe's update_subscription each time
the membership count changes.
"""

from __future__ import annotations

import pytest
from better_auth.auth import init
from better_auth.plugins import email_and_password
from better_auth.plugins.organization import organization
from better_auth.types.adapter import Where
from better_auth.types.init_options import BetterAuthOptions
from better_auth_memory_adapter import memory_adapter
from better_auth_stripe import stripe
from better_auth_stripe.client import StripeClient
from better_auth_stripe.schema import StripeOptions, StripePlan
from better_auth_test_utils import ASGIDriver, MockStripe


async def _build_driver() -> tuple[ASGIDriver, MockStripe, object]:
    import asyncio

    mock = MockStripe()
    sclient = StripeClient(api_key="sk_test", transport=mock.mock_transport())
    options = StripeOptions(
        stripe_client=sclient,
        webhook_secret="whsec_test",
        plans={"team": StripePlan(name="team", price_id="price_team", seats=True)},
        subscription_for="organization",
    )
    auth = init(
        BetterAuthOptions(
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


async def _create_org_with_active_sub(auth, mock: MockStripe, owner_id: str) -> tuple[str, str]:
    """Create an org owned by `owner_id` plus an active seat subscription on it.

    Returns `(org_id, stripe_sub_id)`. We skip Stripe's checkout flow and write the
    subscription row directly because seat-sync only watches member changes — we
    don't need the full checkout to test it.
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
    # Create a real Stripe subscription via the mock so its id is in mock.subscriptions
    stripe_sub = await auth.context.adapter.create(  # local row first
        model="subscription",
        data={
            "plan": "team",
            "referenceId": org["id"],
            "stripeCustomerId": "cus_test",
            "stripeSubscriptionId": "sub_test_1",
            "status": "active",
            "seats": 1,
        },
    )
    mock.subscriptions["sub_test_1"] = {
        "id": "sub_test_1",
        "object": "subscription",
        "status": "active",
        "items": {"data": [{"price": {"id": "price_team"}, "quantity": 1}]},
    }
    return org["id"], stripe_sub["id"]


async def _set_active_org(auth, user_id: str, org_id: str) -> None:
    sess_row = await auth.context.adapter.find_one(
        model="session", where=(Where(field="userId", value=user_id),)
    )
    await auth.context.adapter.update(
        model="session",
        where=(Where(field="id", value=sess_row["id"]),),
        update={"activeOrganizationId": org_id},
    )


@pytest.mark.asyncio
async def test_seat_sync_increments_on_invite_accept() -> None:
    driver, mock, auth = await _build_driver()
    owner = await _sign_up(driver, "owner@example.com")
    org_id, _ = await _create_org_with_active_sub(auth, mock, owner["id"])
    await _set_active_org(auth, owner["id"], org_id)

    # Create the invite via the org plugin's API
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

    # Newbie signs up and accepts the invite
    driver2 = ASGIDriver(app=auth.router.mount())
    await _sign_up(driver2, "newbie@example.com")
    r = await driver2.request(
        "POST",
        "/organization/accept-invitation",
        json_body={"invitationId": invitation_id},
    )
    assert r.status == 200, r.json()

    # Seat-sync should have fired an update_subscription with quantity=2
    updates = [e for e in mock.capture_events if e["type"] == "subscription.update"]
    assert updates, "expected at least one Stripe subscription.update event"
    # MockStripe records the request body verbatim; httpx form-encodes ints as strings.
    sent_quantities = [str(e["object"].get("quantity")) for e in updates]
    assert "2" in sent_quantities, f"expected quantity=2 in updates: {sent_quantities}"

    # Local subscription row reflects the new seat count
    row = await auth.context.adapter.find_one(
        model="subscription",
        where=(Where(field="stripeSubscriptionId", value="sub_test_1"),),
    )
    assert row["seats"] == 2


@pytest.mark.asyncio
async def test_seat_sync_decrements_on_remove_member() -> None:
    driver, mock, auth = await _build_driver()
    owner = await _sign_up(driver, "owner@example.com")
    org_id, _ = await _create_org_with_active_sub(auth, mock, owner["id"])
    await _set_active_org(auth, owner["id"], org_id)

    # Add a second member directly (skip the invite dance — not what we're testing)
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

    # Owner removes the member via the org route
    r = await driver.request(
        "POST",
        "/organization/remove-member",
        json_body={"organizationId": org_id, "memberIdOrEmail": member_row["id"]},
    )
    assert r.status == 200, r.json()

    # Quantity should have been pushed back to 1 (owner left after second-member removed)
    updates = [e for e in mock.capture_events if e["type"] == "subscription.update"]
    assert updates, "expected at least one Stripe subscription.update event"
    sent_quantities = [str(e["object"].get("quantity")) for e in updates]
    assert "1" in sent_quantities, f"expected quantity=1 in updates: {sent_quantities}"


@pytest.mark.asyncio
async def test_seat_sync_no_op_for_user_billed_plans() -> None:
    """Sanity: if subscription_for='user' OR plan.seats=False, no listener registers."""
    import asyncio
    mock = MockStripe()
    sclient = StripeClient(api_key="sk_test", transport=mock.mock_transport())
    options = StripeOptions(
        stripe_client=sclient,
        webhook_secret="whsec_test",
        plans={"pro": StripePlan(name="pro", price_id="price_pro", seats=False)},
        subscription_for="user",
    )
    auth = init(
        BetterAuthOptions(
            database=memory_adapter(),
            secret="s",
            plugins=[email_and_password(), organization(), stripe(options)],
        )
    )
    await asyncio.sleep(0)
    await asyncio.sleep(0)
    driver = ASGIDriver(app=auth.router.mount())
    owner = await _sign_up(driver, "owner@example.com")
    # Build an org + member directly. Nothing should fire on Stripe.
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
    # Trigger an event manually via the bus to confirm no listener picks it up
    from better_auth.events import MemberEvent, get_bus

    await get_bus(auth.context).emit(
        "organization.member.added",
        MemberEvent(organization_id=org["id"], user_id="someone", role="member", action="added"),
    )
    # No subscription.update events because seat-sync didn't register
    assert all(e["type"] != "subscription.update" for e in mock.capture_events)
