"""Stripe webhook signature verification.

Mirrors Stripe's documented `Stripe-Signature` scheme: a header of the form
`t=<unix_seconds>,v1=<hex_hmac_sha256>` over `<unix_seconds>.<body>` keyed by
the webhook secret. We re-implement it instead of delegating to
`stripe.WebhookSignature` so the verifier remains injectable / async-friendly
in tests (and we don't carry an extra dependency on stripe internals).
"""

from __future__ import annotations

import hashlib
import hmac
import time

from better_auth.error import APIError


def verify_signature(
    payload: bytes,
    signature_header: str,
    secret: str,
    *,
    tolerance: int = 300,
) -> None:
    """Verify a Stripe-Signature header against the payload.

    Raises `APIError(400, "INVALID_SIGNATURE")` on any failure (missing
    timestamp, missing v1, stale timestamp, or HMAC mismatch).
    """
    parts: dict[str, list[str]] = {}
    for piece in (signature_header or "").split(","):
        k, _, v = piece.strip().partition("=")
        if not k or not v:
            continue
        parts.setdefault(k, []).append(v)

    timestamps = parts.get("t", [])
    sigs = parts.get("v1", [])
    if not timestamps or not sigs:
        raise APIError(400, "INVALID_SIGNATURE", message="missing t or v1 component")
    timestamp = timestamps[0]
    try:
        ts_int = int(timestamp)
    except ValueError:
        raise APIError(400, "INVALID_SIGNATURE", message="bad timestamp") from None
    if tolerance > 0 and abs(int(time.time()) - ts_int) > tolerance:
        raise APIError(400, "INVALID_SIGNATURE", message="timestamp outside tolerance")

    signed = f"{timestamp}.".encode("ascii") + payload
    expected = hmac.new(secret.encode("utf-8"), signed, hashlib.sha256).hexdigest()
    if not any(hmac.compare_digest(expected, s) for s in sigs):
        raise APIError(400, "INVALID_SIGNATURE", message="signature mismatch")


__all__ = ["verify_signature"]
