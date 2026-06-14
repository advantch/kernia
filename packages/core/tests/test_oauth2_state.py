"""Unit tests for kernia.oauth2.state — signed state token round-trip."""

from __future__ import annotations

import pytest
from kernia.oauth2.state import generate_state, parse_state


def test_round_trip_minimal() -> None:
    token = generate_state(secret="s", callback_url="https://x/cb", provider_id="google")
    data = parse_state(token, secret="s")
    assert data["callbackURL"] == "https://x/cb"
    assert data["providerId"] == "google"
    assert "nonce" in data
    assert isinstance(data["createdAt"], int)


def test_round_trip_full() -> None:
    token = generate_state(
        secret="s",
        callback_url="https://x/cb",
        provider_id="google",
        error_callback_url="https://x/err",
        new_user_callback_url="https://x/onboard",
        code_verifier="verifier-xyz",
        nonce="nonce-fixed",
        link_to_user_id="user-1",
    )
    data = parse_state(token, secret="s")
    assert data["errorCallbackURL"] == "https://x/err"
    assert data["newUserCallbackURL"] == "https://x/onboard"
    assert data["codeVerifier"] == "verifier-xyz"
    assert data["nonce"] == "nonce-fixed"
    assert data["linkToUserId"] == "user-1"


def test_wrong_secret_fails() -> None:
    token = generate_state(secret="s", callback_url="x", provider_id="google")
    with pytest.raises(ValueError, match="signature"):
        parse_state(token, secret="other")


def test_tampered_payload_fails() -> None:
    token = generate_state(secret="s", callback_url="x", provider_id="google")
    body, _, _sig = token.rpartition(".")
    tampered = body[:-1] + ("A" if body[-1] != "A" else "B") + "." + _sig
    with pytest.raises(ValueError, match="signature"):
        parse_state(tampered, secret="s")


def test_expired_state_rejected() -> None:
    token = generate_state(secret="s", callback_url="x", provider_id="google")
    # parse with a max_age of 0 — already expired
    with pytest.raises(ValueError, match="expired"):
        parse_state(token, secret="s", max_age=0)


def test_malformed_state_rejected() -> None:
    with pytest.raises(ValueError, match="signature"):
        parse_state("not.a.real.state", secret="s")
