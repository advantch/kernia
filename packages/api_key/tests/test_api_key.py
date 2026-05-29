"""Unit tests for the API key plugin's pure helpers.

Endpoint / flow behavior is covered by ``e2e/plugins/test_api_key.py``.
"""

from __future__ import annotations

from better_auth_api_key import (
    default_key_generator,
    default_key_hasher,
    generate_api_key,
    parse_api_key,
)


def test_default_key_generator_length_and_alphabet() -> None:
    key = default_key_generator(64, None)
    assert len(key) == 64
    assert key.isalpha()


def test_default_key_generator_applies_prefix() -> None:
    key = default_key_generator(32, "hello_")
    assert key.startswith("hello_")
    assert len(key) == len("hello_") + 32


def test_default_key_hasher_is_deterministic_base64url() -> None:
    a = default_key_hasher("some-key")
    b = default_key_hasher("some-key")
    assert a == b
    # base64url, no padding
    assert "=" not in a
    assert "+" not in a
    assert "/" not in a
    assert default_key_hasher("other") != a


def test_generate_api_key_returns_start() -> None:
    raw, start = generate_api_key(length=64)
    assert len(raw) == 64
    assert start == raw[:6]


def test_generate_api_key_with_prefix() -> None:
    raw, start = generate_api_key(length=16, prefix="pk_")
    assert raw.startswith("pk_")
    assert start == raw[:6]


def test_parse_api_key_handles_empty() -> None:
    assert parse_api_key("") is None
    raw, _ = generate_api_key()
    assert parse_api_key(raw) == raw[:6]
