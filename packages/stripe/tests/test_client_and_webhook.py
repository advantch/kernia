"""Unit tests for the Stripe client + webhook helper.

These complement the wire-level e2e tests in `e2e/plugins/test_stripe.py`. They
exercise the smaller building blocks in isolation so regressions point at the
right module.
"""

from __future__ import annotations

import hashlib
import hmac
import time

import pytest
from kernia.error import APIError
from kernia_stripe import StripeClient, verify_signature
from kernia_test_utils import MockStripe


async def test_stripe_client_creates_customer_through_mock_transport() -> None:
    mock = MockStripe()
    client = StripeClient(api_key="sk_test", transport=mock.mock_transport())
    customer = await client.create_customer(email="x@y.test", name="X", metadata={"userId": "u1"})
    assert customer["id"].startswith("cus_")
    assert customer["email"] == "x@y.test"
    assert mock.customers[customer["id"]]["metadata"] == {"userId": "u1"}


async def test_stripe_client_creates_checkout_session() -> None:
    mock = MockStripe()
    client = StripeClient(api_key="sk_test", transport=mock.mock_transport())
    cust = await client.create_customer(email="x@y.test", name=None)
    session = await client.create_checkout_session(
        mode="subscription",
        customer=cust["id"],
        success_url="https://app/success",
        cancel_url="https://app/cancel",
        line_items=[{"price": "price_pro", "quantity": 1}],
        metadata={"referenceId": "u1"},
    )
    assert session["url"].startswith("https://checkout.stripe.test/")
    assert session["customer"] == cust["id"]


async def test_verify_signature_accepts_well_formed_header() -> None:
    body = b'{"hello":"world"}'
    ts = int(time.time())
    sig = hmac.new(b"secret", f"{ts}.".encode("ascii") + body, hashlib.sha256).hexdigest()
    verify_signature(body, f"t={ts},v1={sig}", "secret")


def test_verify_signature_rejects_bad_hmac() -> None:
    body = b"{}"
    ts = int(time.time())
    bad = "f" * 64
    with pytest.raises(APIError) as exc:
        verify_signature(body, f"t={ts},v1={bad}", "secret")
    assert exc.value.code == "INVALID_SIGNATURE"


def test_verify_signature_rejects_stale_timestamp() -> None:
    body = b"{}"
    old_ts = int(time.time()) - 10_000
    sig = hmac.new(b"secret", f"{old_ts}.".encode("ascii") + body, hashlib.sha256).hexdigest()
    with pytest.raises(APIError) as exc:
        verify_signature(body, f"t={old_ts},v1={sig}", "secret", tolerance=60)
    assert exc.value.code == "INVALID_SIGNATURE"


def test_mock_stripe_round_trip_emit_webhook() -> None:
    payload, headers = MockStripe.emit_webhook({"type": "evt", "data": {"object": {}}}, "secret")
    sig = headers["Stripe-Signature"].lower()
    # Sanity-check the signature would pass verify_signature.
    verify_signature(payload, sig, "secret")
