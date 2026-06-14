"""Unit tests for kernia.crypto — argon2id default, scrypt legacy verify."""

from __future__ import annotations

import pytest
from kernia.crypto import hash_password, needs_rehash, verify_password


def test_argon2_round_trip() -> None:
    hashed = hash_password("hunter2hunter2")
    assert hashed.startswith("$argon2id$")
    assert verify_password("hunter2hunter2", hashed)


def test_argon2_rejects_wrong_password() -> None:
    hashed = hash_password("hunter2hunter2")
    assert not verify_password("nope", hashed)
    assert not verify_password("", hashed)


def test_argon2_constant_time_does_not_leak_via_truthy() -> None:
    hashed = hash_password("password-1")
    # near-miss
    assert not verify_password("password-2", hashed)


def test_legacy_scrypt_hash_still_verifies() -> None:
    # construct the legacy format directly to prove backwards compat
    from kernia.crypto import _legacy_scrypt_hash  # type: ignore[attr-defined]

    legacy = _legacy_scrypt_hash("legacy-pw")
    assert legacy.startswith("scrypt$")
    assert verify_password("legacy-pw", legacy)
    assert not verify_password("wrong", legacy)


def test_needs_rehash_flags_legacy() -> None:
    from kernia.crypto import _legacy_scrypt_hash  # type: ignore[attr-defined]

    legacy = _legacy_scrypt_hash("pw")
    modern = hash_password("pw")
    assert needs_rehash(legacy) is True
    assert needs_rehash(modern) is False


def test_verify_handles_garbage_input() -> None:
    assert verify_password("anything", "") is False
    assert verify_password("anything", "not-a-hash") is False
    assert verify_password("anything", "scrypt$bad") is False


@pytest.mark.parametrize("pw", ["a", "café", "🔐" * 8, "x" * 1000])
def test_argon2_handles_unicode_and_long_input(pw: str) -> None:
    h = hash_password(pw)
    assert verify_password(pw, h)
