"""getCheckoutSessionParams merge semantics on `/subscription/upgrade`.

Ports the `describe("getCheckoutSessionParams subscription_data merge")` block of
`reference/packages/stripe/test/checkout.test.ts`.

Upstream lets a `getCheckoutSessionParams` hook customise the Stripe Checkout
session params, but with strict precedence rules:

  * library-owned flow-routing fields (mode/customer/customer_email/success_url/
    cancel_url/line_items/client_reference_id) can never be overridden by the hook,
  * hook `subscription_data` is layered over the library's trial config, and
    internal subscription metadata (userId/subscriptionId/referenceId) is always
    re-applied on top,
  * `customer_update` falls back to a customer-type default unless the hook sets it,
  * request-time `locale` wins over a hook-supplied locale, which in turn beats nothing,
  * arbitrary UX-only params pass straight through.

The Python port wires this in `_upgrade_via_checkout`. A fresh user has no active
Stripe subscription, so `/subscription/upgrade` opens a Checkout session — exactly
the path the hook customises. Assertions read the flat form params MockStripe
captured (`event["params"]`) plus the reconstructed `event["object"]`.
"""

from __future__ import annotations

from typing import Any

from kernia.auth import init
from kernia.plugins import email_and_password
from kernia.types.init_options import (
    KerniaOptions,
    EmailPasswordOptions,
    RateLimitOptions,
)
from kernia_memory_adapter import memory_adapter
from kernia_stripe import StripeClient, StripeOptions, StripePlan, stripe
from kernia_stripe.schema import FreeTrial
from kernia_test_utils import ASGIDriver, MockStripe

WEBHOOK_SECRET = "whsec_test_secret"


def _build(
    *, hook: Any, free_trial_days: int | None = None
) -> tuple[ASGIDriver, MockStripe]:
    mock = MockStripe()
    mock.add_price("price_starter", usage_type="licensed")
    client = StripeClient(api_key="sk_test_x", transport=mock.mock_transport())
    plan = StripePlan(
        name="starter",
        price_id="price_starter",
        free_trial=FreeTrial(days=free_trial_days) if free_trial_days else None,
    )
    plugin = stripe(
        StripeOptions(
            stripe_client=client,
            webhook_secret=WEBHOOK_SECRET,
            plans={"starter": plan},
            get_checkout_session_params=hook,
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
    return ASGIDriver(app=auth.router.mount()), mock


async def _signup(driver: ASGIDriver, email: str) -> None:
    r = await driver.request(
        "POST", "/sign-up/email", json_body={"email": email, "password": "longstrongpw"}
    )
    assert r.status == 200, r.json()


async def _upgrade(driver: ASGIDriver, **extra: Any) -> dict:
    body = {
        "plan": "starter",
        "successUrl": "https://app.test/success",
        "cancelUrl": "https://app.test/cancel",
        **extra,
    }
    return await driver.request("POST", "/subscription/upgrade", json_body=body)


def _checkout_event(mock: MockStripe) -> dict:
    return next(
        e for e in mock.capture_events if e["type"] == "checkout.session.create"
    )


# ---------------------------------------------------------------------------
# subscription_data + metadata merge
# ---------------------------------------------------------------------------


async def test_preserves_plan_free_trial_with_custom_subscription_data() -> None:
    async def hook(_data: Any, _req: Any, _ctx: Any) -> dict:
        return {
            "params": {
                "payment_method_collection": "if_required",
                "subscription_data": {
                    "trial_settings": {
                        "end_behavior": {"missing_payment_method": "cancel"}
                    }
                },
            }
        }

    driver, mock = _build(hook=hook, free_trial_days=14)
    await _signup(driver, "trial-merge@email.com")
    r = await _upgrade(driver)
    assert r.status == 200, r.json()
    params = _checkout_event(mock)["params"]
    # Library trial preserved AND hook subscription_data merged in.
    assert params["subscription_data[trial_period_days]"] == "14"
    assert (
        params["subscription_data[trial_settings][end_behavior][missing_payment_method]"]
        == "cancel"
    )


async def test_preserves_internal_subscription_metadata() -> None:
    async def hook(_data: Any, _req: Any, _ctx: Any) -> dict:
        return {
            "params": {
                "subscription_data": {
                    "trial_settings": {
                        "end_behavior": {"missing_payment_method": "cancel"}
                    }
                }
            }
        }

    driver, mock = _build(hook=hook, free_trial_days=14)
    await _signup(driver, "metadata-merge@email.com")
    r = await _upgrade(driver)
    assert r.status == 200, r.json()
    params = _checkout_event(mock)["params"]
    assert params["subscription_data[metadata][userId]"]
    assert params["subscription_data[metadata][subscriptionId]"]
    assert params["subscription_data[metadata][referenceId]"]


# ---------------------------------------------------------------------------
# flow-routing protection
# ---------------------------------------------------------------------------


async def test_hook_cannot_override_flow_routing_fields() -> None:
    async def hook(_data: Any, _req: Any, _ctx: Any) -> dict:
        return {
            "params": {
                "success_url": "https://attacker.example/success",
                "cancel_url": "https://attacker.example/cancel",
                "mode": "payment",
                "client_reference_id": "attacker-controlled",
                "customer": "cus_attacker",
                "customer_email": "attacker@example.com",
                "line_items": [{"price": "price_attacker", "quantity": 99}],
            }
        }

    driver, mock = _build(hook=hook)
    await _signup(driver, "hijack-attempt@email.com")
    r = await _upgrade(driver)
    assert r.status == 200, r.json()
    obj = _checkout_event(mock)["object"]
    assert obj["mode"] == "subscription"
    assert obj["customer"] != "cus_attacker"
    assert obj["customer_email"] != "attacker@example.com"
    assert obj["success_url"] != "https://attacker.example/success"
    assert obj["success_url"] == "https://app.test/success"
    assert obj["cancel_url"] != "https://attacker.example/cancel"
    assert obj["line_items"][0]["price"] == "price_starter"
    assert obj["line_items"][0]["price"] != "price_attacker"


# ---------------------------------------------------------------------------
# UX-only passthrough
# ---------------------------------------------------------------------------


async def test_ux_only_params_pass_through() -> None:
    async def hook(_data: Any, _req: Any, _ctx: Any) -> dict:
        return {
            "params": {
                "allow_promotion_codes": True,
                "payment_method_collection": "if_required",
                "tax_id_collection": {"enabled": True},
                "custom_text": {"submit": {"message": "Welcome aboard"}},
                "billing_address_collection": "required",
            }
        }

    driver, mock = _build(hook=hook)
    await _signup(driver, "passthrough@email.com")
    r = await _upgrade(driver)
    assert r.status == 200, r.json()
    params = _checkout_event(mock)["params"]
    assert params["allow_promotion_codes"] == "true"
    assert params["payment_method_collection"] == "if_required"
    assert params["tax_id_collection[enabled]"] == "true"
    assert params["custom_text[submit][message]"] == "Welcome aboard"
    assert params["billing_address_collection"] == "required"


# ---------------------------------------------------------------------------
# customer_update precedence
# ---------------------------------------------------------------------------


async def test_hook_can_override_customer_update() -> None:
    async def hook(_data: Any, _req: Any, _ctx: Any) -> dict:
        return {"params": {"customer_update": {"name": "never"}}}

    driver, mock = _build(hook=hook)
    await _signup(driver, "customer-update-override@email.com")
    r = await _upgrade(driver)
    assert r.status == 200, r.json()
    assert _checkout_event(mock)["object"]["customer_update"] == {"name": "never"}


async def test_customer_update_falls_back_to_library_default() -> None:
    async def hook(_data: Any, _req: Any, _ctx: Any) -> dict:
        return {"params": {"allow_promotion_codes": True}}

    driver, mock = _build(hook=hook)
    await _signup(driver, "customer-update-default@email.com")
    r = await _upgrade(driver)
    assert r.status == 200, r.json()
    assert _checkout_event(mock)["object"]["customer_update"] == {
        "name": "auto",
        "address": "auto",
    }


# ---------------------------------------------------------------------------
# locale precedence
# ---------------------------------------------------------------------------


async def test_request_locale_wins_over_hook_locale() -> None:
    async def hook(_data: Any, _req: Any, _ctx: Any) -> dict:
        return {"params": {"locale": "ko"}}

    driver, mock = _build(hook=hook)
    await _signup(driver, "locale-request-wins@email.com")
    r = await _upgrade(driver, locale="en")
    assert r.status == 200, r.json()
    assert _checkout_event(mock)["object"]["locale"] == "en"


async def test_falls_back_to_hook_locale_when_request_omits_it() -> None:
    async def hook(_data: Any, _req: Any, _ctx: Any) -> dict:
        return {"params": {"locale": "ko"}}

    driver, mock = _build(hook=hook)
    await _signup(driver, "locale-fallback@email.com")
    r = await _upgrade(driver)
    assert r.status == 200, r.json()
    assert _checkout_event(mock)["object"]["locale"] == "ko"
