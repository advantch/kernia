"""Unit tests for better_auth.crypto.secret_rotation."""

from __future__ import annotations

import pytest

from better_auth.crypto.secret_rotation import (
    normalize_secrets,
    sign_with,
    verify_with_any,
)


def test_normalize_string() -> None:
    assert normalize_secrets("only") == ("only",)


def test_normalize_sequence() -> None:
    assert normalize_secrets(["a", "b", "c"]) == ("a", "b", "c")


def test_normalize_rejects_empty() -> None:
    with pytest.raises(ValueError):
        normalize_secrets([])


def test_active_secret_signs_and_verifies() -> None:
    signed = sign_with("payload", active_secret="active")
    assert verify_with_any(signed, secrets=("active",)) == "payload"


def test_older_secret_verifies_after_rotation() -> None:
    # Cookie signed under the old secret should still verify after rotation
    signed = sign_with("payload", active_secret="old")
    # Caller is now using the new active + old as fallback
    assert verify_with_any(signed, secrets=("new", "old")) == "payload"


def test_unknown_secret_rejected() -> None:
    signed = sign_with("payload", active_secret="active")
    assert verify_with_any(signed, secrets=("other",)) is None


def test_malformed_signed_rejected() -> None:
    assert verify_with_any("no-signature", secrets=("s",)) is None
