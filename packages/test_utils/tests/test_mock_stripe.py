"""MockStripe: REST surface + Stripe-Signature scheme."""

from __future__ import annotations

import hashlib
import hmac
import json

import httpx

from better_auth_test_utils import MockStripe


async def test_create_customer_round_trip() -> None:
    stripe = MockStripe()
    async with httpx.AsyncClient(transport=stripe.mock_transport()) as client:
        r = await client.post(
            "https://api.stripe.com/v1/customers",
            data={"email": "a@b.c", "name": "A", "metadata[user_id]": "u1"},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["email"] == "a@b.c"
        assert body["metadata"] == {"user_id": "u1"}
        cid = body["id"]
        assert cid.startswith("cus_")

        # Retrieve
        r2 = await client.get(f"https://api.stripe.com/v1/customers/{cid}")
        assert r2.status_code == 200
        assert r2.json()["id"] == cid

    assert any(e["type"] == "customer.create" for e in stripe.capture_events)


async def test_checkout_session_create() -> None:
    stripe = MockStripe()
    async with httpx.AsyncClient(transport=stripe.mock_transport()) as client:
        r = await client.post(
            "https://api.stripe.com/v1/checkout/sessions",
            data={
                "mode": "subscription",
                "customer": "cus_x",
                "success_url": "https://ok",
                "cancel_url": "https://no",
            },
        )
        assert r.status_code == 200
        body = r.json()
        assert body["mode"] == "subscription"
        assert body["customer"] == "cus_x"
        assert body["url"].startswith("https://checkout.stripe.test/")


async def test_subscription_retrieve_404() -> None:
    stripe = MockStripe()
    async with httpx.AsyncClient(transport=stripe.mock_transport()) as client:
        r = await client.get("https://api.stripe.com/v1/subscriptions/sub_nope")
        assert r.status_code == 404


def _verify_stripe_signature(body: bytes, sig_header: str, secret: str) -> bool:
    """Replicates Stripe SDK's verification."""
    parts = dict(item.split("=", 1) for item in sig_header.split(","))
    timestamp = parts["t"]
    expected = hmac.new(
        secret.encode("utf-8"),
        f"{timestamp}.".encode("ascii") + body,
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected, parts["v1"])


def test_emit_webhook_signature_matches_stripe_scheme() -> None:
    secret = "whsec_test_secret"
    payload = {"id": "evt_1", "type": "customer.subscription.updated", "data": {}}
    body, headers = MockStripe.emit_webhook(payload, secret)

    # Round-trips
    assert json.loads(body)["id"] == "evt_1"
    assert "Stripe-Signature" in headers
    sig = headers["Stripe-Signature"]
    assert sig.startswith("t=")
    assert ",v1=" in sig
    assert _verify_stripe_signature(body, sig, secret)


def test_emit_webhook_fails_with_wrong_secret() -> None:
    body, headers = MockStripe.emit_webhook({"id": "evt"}, "secret-a")
    assert not _verify_stripe_signature(body, headers["Stripe-Signature"], "secret-b")
