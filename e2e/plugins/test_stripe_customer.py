"""Stripe customer lifecycle on signup / upgrade.

Ports ``reference/packages/stripe/test/customer.test.ts``:

  * a Stripe customer is created on sign-up (``createCustomerOnSignUp``), with
    ``customerType`` + ``userId`` metadata, and is reused (not duplicated) on a
    later ``/subscription/upgrade``.
  * a user email change syncs through to the Stripe customer
    (``customers.retrieve`` → ``customers.update``).
  * ``getCustomerCreateParams`` is invoked and deep-merged (``defu``) into the
    ``customers.create`` params — metadata, custom address, nested objects, and
    the no-callback default path.
  * duplicate-customer prevention: when a *user* Stripe customer already exists
    for the email it is reused; org customers are excluded from the lookup
    (``-metadata["customerType"]:"organization"``).
  * search→list fallback for regions where ``customers.search`` is unavailable,
    on both signup and upgrade.
"""

from __future__ import annotations

from typing import Any

from kernia.auth import init
from kernia.plugins.email_password import email_and_password
from kernia.types.adapter import Where
from kernia.types.init_options import (
    EmailPasswordOptions,
    KerniaOptions,
    RateLimitOptions,
)
from kernia_memory_adapter import memory_adapter
from kernia_stripe import StripeClient, StripeOptions, StripePlan, stripe
from kernia_test_utils import ASGIDriver, MockStripe

WEBHOOK_SECRET = "whsec_test_secret"


def _build(
    *,
    create_customer_on_sign_up: bool = True,
    get_customer_create_params: Any = None,
) -> tuple[ASGIDriver, MockStripe, object]:
    mock = MockStripe()
    mock.add_price("price_starter", usage_type="licensed")
    client = StripeClient(api_key="sk_test_x", transport=mock.mock_transport())
    plugin = stripe(
        StripeOptions(
            stripe_client=client,
            webhook_secret=WEBHOOK_SECRET,
            create_customer_on_sign_up=create_customer_on_sign_up,
            get_customer_create_params=get_customer_create_params,
            plans={"starter": StripePlan(name="starter", price_id="price_starter")},
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


async def _signup(driver: ASGIDriver, email: str, name: str = "Test User") -> str:
    r = await driver.request(
        "POST",
        "/sign-up/email",
        json_body={"email": email, "password": "longstrongpw", "name": name},
    )
    assert r.status == 200, r.json()
    return r.json()["user"]["id"]


async def _signin(driver: ASGIDriver, email: str) -> None:
    r = await driver.request(
        "POST",
        "/sign-in/email",
        json_body={"email": email, "password": "longstrongpw"},
    )
    assert r.status == 200, r.json()


def _creates(mock: MockStripe) -> list[dict[str, Any]]:
    return [e for e in mock.capture_events if e["type"] == "customer.create"]


def _seed_customer(mock: MockStripe, cid: str, *, email: str, metadata: dict[str, Any]) -> None:
    mock.customers[cid] = {
        "id": cid,
        "object": "customer",
        "email": email,
        "name": None,
        "metadata": metadata,
    }


# ---------------------------------------------------------------------------
# signup customer creation + reuse
# ---------------------------------------------------------------------------


async def test_creates_customer_on_sign_up() -> None:
    driver, _mock, auth = _build()
    adapter = auth.context.adapter  # type: ignore[attr-defined]
    uid = await _signup(driver, "signup-customer@email.com")

    user = await adapter.find_one(model="user", where=(Where(field="id", value=uid),))
    assert user is not None
    assert user.get("stripeCustomerId")


async def test_customers_create_called_once_for_signup_and_upgrade() -> None:
    driver, mock, _auth = _build()
    await _signup(driver, "single-create@email.com")
    await _signin(driver, "single-create@email.com")

    r = await driver.request("POST", "/subscription/upgrade", json_body={"plan": "starter"})
    assert r.status == 200, r.json()
    assert len(_creates(mock)) == 1


async def test_updates_stripe_customer_email_on_user_email_change() -> None:
    driver, mock, auth = _build()
    adapter = auth.context.adapter  # type: ignore[attr-defined]
    uid = await _signup(driver, "old-email@email.com")
    user = await adapter.find_one(model="user", where=(Where(field="id", value=uid),))
    cid = user["stripeCustomerId"]
    assert mock.customers[cid]["email"] == "old-email@email.com"

    # Update the user email through with_hooks so the Stripe update.after hook fires.
    await auth.context.with_hooks.update(  # type: ignore[attr-defined]
        model="user",
        where=(Where(field="id", value=uid),),
        data={"email": "new-email@example.com"},
    )

    assert mock.customers[cid]["email"] == "new-email@example.com"


# ---------------------------------------------------------------------------
# getCustomerCreateParams
# ---------------------------------------------------------------------------


async def test_get_customer_create_params_merges_metadata() -> None:
    received: list[Any] = []

    async def get_params(user: Any, *_a: Any) -> dict[str, Any]:
        received.append(user)
        return {"metadata": {"customField": "customValue"}}

    driver, mock, _auth = _build(get_customer_create_params=get_params)
    uid = await _signup(driver, "custom-params@email.com", name="Custom User")

    assert received and received[0]["id"] == uid
    obj = _creates(mock)[0]["object"]
    assert obj["email"] == "custom-params@email.com"
    assert obj["name"] == "Custom User"
    assert obj["metadata"]["userId"] == uid
    assert obj["metadata"]["customField"] == "customValue"


async def test_get_customer_create_params_custom_address() -> None:
    async def get_params(*_a: Any) -> dict[str, Any]:
        return {
            "address": {
                "line1": "123 Main St",
                "city": "San Francisco",
                "state": "CA",
                "postal_code": "94111",
                "country": "US",
            }
        }

    driver, mock, _auth = _build(get_customer_create_params=get_params)
    await _signup(driver, "address-user@email.com", name="Address User")

    params = _creates(mock)[0]["params"]
    assert params["address[line1]"] == "123 Main St"
    assert params["address[city]"] == "San Francisco"
    assert params["address[country]"] == "US"


async def test_get_customer_create_params_defu_nested_merge() -> None:
    async def get_params(*_a: Any) -> dict[str, Any]:
        return {
            "metadata": {"customField": "customValue", "anotherField": "anotherValue"},
            "phone": "+1234567890",
        }

    driver, mock, _auth = _build(get_customer_create_params=get_params)
    uid = await _signup(driver, "merge-test@email.com", name="Merge User")

    obj = _creates(mock)[0]["object"]
    assert obj["metadata"] == {
        "customerType": "user",
        "userId": uid,
        "customField": "customValue",
        "anotherField": "anotherValue",
    }
    assert _creates(mock)[0]["params"]["phone"] == "+1234567890"


async def test_works_without_get_customer_create_params() -> None:
    driver, mock, _auth = _build()
    uid = await _signup(driver, "no-custom-params@email.com", name="Default User")

    obj = _creates(mock)[0]["object"]
    assert obj["email"] == "no-custom-params@email.com"
    assert obj["name"] == "Default User"
    assert obj["metadata"] == {"customerType": "user", "userId": uid}


# ---------------------------------------------------------------------------
# duplicate-customer prevention on signup
# ---------------------------------------------------------------------------


async def test_no_duplicate_customer_when_email_exists_in_stripe() -> None:
    driver, mock, auth = _build()
    adapter = auth.context.adapter  # type: ignore[attr-defined]
    _seed_customer(
        mock,
        "cus_stripe_existing_456",
        email="duplicate-email@example.com",
        metadata={"customerType": "user", "userId": "old"},
    )

    uid = await _signup(driver, "duplicate-email@example.com")

    assert not _creates(mock), "should not create a duplicate customer"
    user = await adapter.find_one(model="user", where=(Where(field="id", value=uid),))
    assert user["stripeCustomerId"] == "cus_stripe_existing_456"


async def test_creates_customer_when_none_exists() -> None:
    driver, mock, auth = _build()
    adapter = auth.context.adapter  # type: ignore[attr-defined]
    uid = await _signup(driver, "brand-new@example.com", name="Brand New User")

    assert len(_creates(mock)) == 1
    obj = _creates(mock)[0]["object"]
    assert obj["metadata"] == {"customerType": "user", "userId": uid}
    user = await adapter.find_one(model="user", where=(Where(field="id", value=uid),))
    assert user.get("stripeCustomerId")


# ---------------------------------------------------------------------------
# user/organization customer collision prevention
# ---------------------------------------------------------------------------


async def test_user_signup_does_not_reuse_org_customer() -> None:
    driver, mock, auth = _build()
    adapter = auth.context.adapter  # type: ignore[attr-defined]
    # Only an *organization* customer exists with the shared email — it must be
    # excluded by the search query, forcing a new user customer.
    _seed_customer(
        mock,
        "cus_org_123",
        email="shared@example.com",
        metadata={"customerType": "organization", "organizationId": "org_x"},
    )

    uid = await _signup(driver, "shared@example.com", name="User With Shared Email")

    assert len(_creates(mock)) == 1
    obj = _creates(mock)[0]["object"]
    assert obj["metadata"] == {"customerType": "user", "userId": uid}
    user = await adapter.find_one(model="user", where=(Where(field="id", value=uid),))
    assert user["stripeCustomerId"] != "cus_org_123"


async def test_finds_existing_user_customer_when_org_also_exists() -> None:
    driver, mock, auth = _build()
    adapter = auth.context.adapter  # type: ignore[attr-defined]
    _seed_customer(
        mock,
        "cus_user_existing_789",
        email="both-exist@example.com",
        metadata={"customerType": "user", "userId": "some-old-user-id"},
    )
    _seed_customer(
        mock,
        "cus_org_both",
        email="both-exist@example.com",
        metadata={"customerType": "organization", "organizationId": "org_y"},
    )

    uid = await _signup(driver, "both-exist@example.com", name="User Reclaiming")

    assert not _creates(mock), "should reuse the existing user customer"
    user = await adapter.find_one(model="user", where=(Where(field="id", value=uid),))
    assert user["stripeCustomerId"] == "cus_user_existing_789"


# ---------------------------------------------------------------------------
# search→list fallback for unsupported regions
# ---------------------------------------------------------------------------


async def test_search_fallback_to_list_on_signup() -> None:
    driver, mock, auth = _build()
    adapter = auth.context.adapter  # type: ignore[attr-defined]
    _seed_customer(
        mock,
        "cus_fallback_123",
        email="fallback-user@example.com",
        metadata={"customerType": "user"},
    )
    mock.search_unavailable = True

    uid = await _signup(driver, "fallback-user@example.com", name="Fallback User")

    assert not _creates(mock), "list fallback should have found the existing customer"
    user = await adapter.find_one(model="user", where=(Where(field="id", value=uid),))
    assert user["stripeCustomerId"] == "cus_fallback_123"


async def test_search_fallback_to_list_on_upgrade() -> None:
    driver, mock, auth = _build(create_customer_on_sign_up=False)
    adapter = auth.context.adapter  # type: ignore[attr-defined]
    uid = await _signup(driver, "fallback-upgrade@example.com", name="Fallback Upgrade")
    # No customer linked at signup (create_customer_on_sign_up=False).
    assert not (await adapter.find_one(model="user", where=(Where(field="id", value=uid),))).get(
        "stripeCustomerId"
    )

    _seed_customer(
        mock,
        "cus_fallback_upgrade_123",
        email="fallback-upgrade@example.com",
        metadata={"customerType": "user"},
    )
    mock.search_unavailable = True

    await _signin(driver, "fallback-upgrade@example.com")
    r = await driver.request("POST", "/subscription/upgrade", json_body={"plan": "starter"})
    assert r.status == 200, r.json()

    assert not _creates(mock), "upgrade should reuse the list-fallback customer"
    user = await adapter.find_one(model="user", where=(Where(field="id", value=uid),))
    assert user["stripeCustomerId"] == "cus_fallback_upgrade_123"
