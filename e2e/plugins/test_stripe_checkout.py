"""Multiset line-item diff on plan change (immediate + scheduled).

Ports the line-item describe blocks of
``reference/packages/stripe/test/checkout.test.ts``:

  * ``line item replacement on plan change`` — swapping the base price in place
    while deleting the old plan's line items and adding the new plan's, both for
    an immediate ``subscriptions.update`` and for the deferred
    Subscription-Schedule phase.
  * ``line item add/remove on asymmetric plan change`` — upgrading to a plan
    with *more* line items (base update + delete + 2 adds) and downgrading to a
    plan with *fewer* (base update + 2 deletes + 1 add).
  * ``duplicate line item prevention`` — a line item already present on the
    subscription (or scheduled phase) is not added a second time.

Divergence note: the Python port routes *all* immediate upgrades through
``subscriptions.update`` (see ``test_stripe_seat_swap.py``), so these tests
assert the multiset payload on ``subscriptions.update`` for every case. The
item-diff semantics (in-place base swap, deletes for removed prices, adds for
introduced prices, no duplicates) are identical to upstream.
"""

from __future__ import annotations

from typing import Any

from kernia.auth import init
from kernia.plugins.email_password import email_and_password
from kernia.types.adapter import Where
from kernia.types.init_options import (
    KerniaOptions,
    EmailPasswordOptions,
    RateLimitOptions,
)
from kernia_memory_adapter import memory_adapter
from kernia_stripe import StripeClient, StripeOptions, StripePlan, stripe
from kernia_test_utils import ASGIDriver, MockStripe

WEBHOOK_SECRET = "whsec_test_secret"
CUSTOMER_ID = "cus_mock123"


def _build(plans: dict[str, StripePlan]) -> tuple[ASGIDriver, MockStripe, object]:
    mock = MockStripe()
    client = StripeClient(api_key="sk_test_x", transport=mock.mock_transport())
    plugin = stripe(
        StripeOptions(
            stripe_client=client,
            webhook_secret=WEBHOOK_SECRET,
            create_customer_on_sign_up=True,
            plans=plans,
        )
    )
    auth = init(
        KerniaOptions(
            database=memory_adapter(),
            secret="stripe-secret",
            email_and_password=EmailPasswordOptions(enabled=True),
            plugins=[email_and_password(), plugin],
            rate_limit=RateLimitOptions(enabled=False),
        )
    )
    return ASGIDriver(app=auth.router.mount()), mock, auth


async def _signup_signin(driver: ASGIDriver, auth: object, email: str) -> str:
    r = await driver.request(
        "POST",
        "/sign-up/email",
        json_body={"email": email, "password": "longstrongpw", "name": email},
    )
    assert r.status == 200, r.json()
    user_id = r.json()["user"]["id"]
    await auth.context.adapter.update(  # type: ignore[attr-defined]
        model="user",
        where=(Where(field="id", value=user_id),),
        update={"stripeCustomerId": CUSTOMER_ID},
    )
    r = await driver.request(
        "POST",
        "/sign-in/email",
        json_body={"email": email, "password": "longstrongpw"},
    )
    assert r.status == 200, r.json()
    return user_id


async def _seed_sub(
    auth: object,
    mock: MockStripe,
    *,
    user_id: str,
    plan: str,
    sub_id: str,
    items: list[dict[str, Any]],
) -> None:
    await auth.context.adapter.create(  # type: ignore[attr-defined]
        model="subscription",
        data={
            "plan": plan,
            "referenceId": user_id,
            "status": "active",
            "stripeSubscriptionId": sub_id,
            "stripeCustomerId": CUSTOMER_ID,
        },
    )
    mock.add_subscription(sub_id, customer=CUSTOMER_ID, items=items)


async def _upgrade(driver: ASGIDriver, *, plan: str, schedule: bool = False) -> Any:
    body: dict[str, Any] = {"plan": plan}
    if schedule:
        body["scheduleAtPeriodEnd"] = True
    return await driver.request("POST", "/subscription/upgrade", json_body=body)


def _update_event(mock: MockStripe) -> dict[str, Any]:
    return next(e for e in mock.capture_events if e["type"] == "subscription.update")


def _sched_update_event(mock: MockStripe) -> dict[str, Any]:
    return next(
        e
        for e in mock.capture_events
        if e["type"] == "subscription_schedule.update"
    )


def _parse_bracket_items(params: dict[str, str], prefix: str) -> list[dict[str, Any]]:
    """Reassemble bracket-encoded ``<prefix>[i][field]`` into a list of dicts."""
    open_br = prefix + "["
    items: dict[int, dict[str, Any]] = {}
    for k, v in params.items():
        if not k.startswith(open_br):
            continue
        rest = k[len(open_br) :]
        idx_str, _, field_part = rest.partition("]")
        try:
            idx = int(idx_str)
        except ValueError:
            continue
        field = field_part.lstrip("[").rstrip("]")
        items.setdefault(idx, {})[field] = v
    return [items[i] for i in sorted(items)]


def _payload_items(mock: MockStripe) -> list[dict[str, Any]]:
    return _parse_bracket_items(_update_event(mock)["params"], "items")


def _phase2_items(mock: MockStripe) -> list[dict[str, Any]]:
    return _parse_bracket_items(
        _sched_update_event(mock)["params"], "phases[1][items]"
    )


def _by_id(items: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {it["id"]: it for it in items if it.get("id")}


# ---------------------------------------------------------------------------
# line item replacement on plan change
# ---------------------------------------------------------------------------


def _replacement_plans() -> dict[str, StripePlan]:
    return {
        "starter": StripePlan(
            name="starter",
            price_id="price_starter_base",
            line_items=[
                {"price": "price_starter_events"},
                {"price": "price_starter_security"},
            ],
        ),
        "pro": StripePlan(
            name="pro",
            price_id="price_pro_base",
            line_items=[
                {"price": "price_pro_events"},
                {"price": "price_pro_security"},
            ],
        ),
    }


async def test_swaps_line_item_prices_when_upgrading_immediately() -> None:
    driver, mock, auth = _build(_replacement_plans())
    uid = await _signup_signin(driver, auth, "lineitem-upgrade@email.com")
    await _seed_sub(
        auth,
        mock,
        user_id=uid,
        plan="starter",
        sub_id="sub_lineitem",
        items=[
            {"id": "si_base", "price": "price_starter_base", "quantity": 1},
            {"id": "si_events", "price": "price_starter_events"},
            {"id": "si_security", "price": "price_starter_security"},
        ],
    )

    r = await _upgrade(driver, plan="pro")
    assert r.status == 200, r.json()

    assert not [
        e for e in mock.capture_events if e["type"] == "billing_portal.session.create"
    ]
    event = _update_event(mock)
    assert event["object"]["id"] == "sub_lineitem"

    items = _payload_items(mock)
    # Multiset diff: base update + 2 deletes + 2 adds.
    assert len(items) == 5
    by_id = _by_id(items)
    assert by_id["si_base"]["price"] == "price_pro_base"
    assert by_id["si_events"].get("deleted") == "true"
    assert by_id["si_security"].get("deleted") == "true"
    adds = {it["price"] for it in items if not it.get("id")}
    assert adds == {"price_pro_events", "price_pro_security"}


async def test_swaps_line_item_prices_in_scheduled_phase() -> None:
    driver, mock, auth = _build(_replacement_plans())
    uid = await _signup_signin(driver, auth, "lineitem-schedule@email.com")
    await _seed_sub(
        auth,
        mock,
        user_id=uid,
        plan="pro",
        sub_id="sub_lineitem_sched",
        items=[
            {"id": "si_base", "price": "price_pro_base", "quantity": 1},
            {"id": "si_events", "price": "price_pro_events"},
            {"id": "si_security", "price": "price_pro_security"},
        ],
    )

    r = await _upgrade(driver, plan="starter", schedule=True)
    assert r.status == 200, r.json()

    assert [
        e for e in mock.capture_events if e["type"] == "subscription_schedule.create"
    ]
    phase2 = _phase2_items(mock)
    # Multiset diff: base in-place, old line items removed, new added.
    assert len(phase2) == 3
    prices = {it["price"] for it in phase2}
    assert prices == {
        "price_starter_base",
        "price_starter_events",
        "price_starter_security",
    }


# ---------------------------------------------------------------------------
# line item add/remove on asymmetric plan change
# ---------------------------------------------------------------------------


def _asymmetric_plans() -> dict[str, StripePlan]:
    return {
        "basic": StripePlan(
            name="basic",
            price_id="price_basic_base",
            line_items=[{"price": "price_basic_events"}],
        ),
        "premium": StripePlan(
            name="premium",
            price_id="price_premium_base",
            line_items=[
                {"price": "price_premium_events"},
                {"price": "price_premium_security"},
            ],
        ),
    }


async def test_adds_new_line_items_when_upgrading_to_richer_plan() -> None:
    driver, mock, auth = _build(_asymmetric_plans())
    uid = await _signup_signin(driver, auth, "asymmetric-up@email.com")
    await _seed_sub(
        auth,
        mock,
        user_id=uid,
        plan="basic",
        sub_id="sub_asym_up",
        items=[
            {"id": "si_base", "price": "price_basic_base", "quantity": 1},
            {"id": "si_events", "price": "price_basic_events"},
        ],
    )

    r = await _upgrade(driver, plan="premium")
    assert r.status == 200, r.json()

    items = _payload_items(mock)
    # Multiset diff: base update + 1 delete + 2 adds.
    assert len(items) == 4
    by_id = _by_id(items)
    assert by_id["si_base"]["price"] == "price_premium_base"
    assert by_id["si_events"].get("deleted") == "true"
    adds = {it["price"] for it in items if not it.get("id")}
    assert adds == {"price_premium_events", "price_premium_security"}


async def test_removes_extra_line_items_when_downgrading() -> None:
    driver, mock, auth = _build(_asymmetric_plans())
    uid = await _signup_signin(driver, auth, "asymmetric-down@email.com")
    await _seed_sub(
        auth,
        mock,
        user_id=uid,
        plan="premium",
        sub_id="sub_asym_down",
        items=[
            {"id": "si_base", "price": "price_premium_base", "quantity": 1},
            {"id": "si_events", "price": "price_premium_events"},
            {"id": "si_security", "price": "price_premium_security"},
        ],
    )

    r = await _upgrade(driver, plan="basic")
    assert r.status == 200, r.json()

    items = _payload_items(mock)
    # Multiset diff: base update + 2 deletes + 1 add.
    assert len(items) == 4
    by_id = _by_id(items)
    assert by_id["si_base"]["price"] == "price_basic_base"
    assert by_id["si_events"].get("deleted") == "true"
    assert by_id["si_security"].get("deleted") == "true"
    adds = {it["price"] for it in items if not it.get("id")}
    assert adds == {"price_basic_events"}


# ---------------------------------------------------------------------------
# duplicate line item prevention
# ---------------------------------------------------------------------------


async def test_does_not_duplicate_present_line_item_immediate() -> None:
    driver, mock, auth = _build(_asymmetric_plans())
    uid = await _signup_signin(driver, auth, "dup-lineitem@email.com")
    # The subscription already carries price_premium_security on a stale item.
    await _seed_sub(
        auth,
        mock,
        user_id=uid,
        plan="basic",
        sub_id="sub_dup",
        items=[
            {"id": "si_base", "price": "price_basic_base", "quantity": 1},
            {"id": "si_events", "price": "price_basic_events"},
            {"id": "si_stale", "price": "price_premium_security"},
        ],
    )

    r = await _upgrade(driver, plan="premium")
    assert r.status == 200, r.json()

    items = _payload_items(mock)
    # si_stale already carries price_premium_security, so it must NOT be re-added.
    security_adds = [
        it
        for it in items
        if not it.get("id") and it.get("price") == "price_premium_security"
    ]
    assert security_adds == []


async def test_does_not_duplicate_present_line_item_scheduled() -> None:
    driver, mock, auth = _build(_asymmetric_plans())
    uid = await _signup_signin(driver, auth, "dup-lineitem-sched@email.com")
    await _seed_sub(
        auth,
        mock,
        user_id=uid,
        plan="basic",
        sub_id="sub_dup_sched",
        items=[
            {"id": "si_base", "price": "price_basic_base", "quantity": 1},
            {"id": "si_events", "price": "price_basic_events"},
            {"id": "si_stale", "price": "price_premium_security"},
        ],
    )

    r = await _upgrade(driver, plan="premium", schedule=True)
    assert r.status == 200, r.json()

    phase2 = _phase2_items(mock)
    # price_premium_security should appear only once.
    security = [it for it in phase2 if it.get("price") == "price_premium_security"]
    assert len(security) == 1
