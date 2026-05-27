"""Unit tests for the device-authorization code generators."""

from __future__ import annotations

from kernia.plugins.device_authorization.routes import (
    DEVICE_CODE_CHARSET,
    USER_CODE_CHARSET,
    _generate_device_code,
    _generate_user_code,
)


def test_user_code_uses_friendly_charset() -> None:
    # No vowels, no 0/O/1/I, etc.
    assert "A" not in USER_CODE_CHARSET
    assert "E" not in USER_CODE_CHARSET
    assert "I" not in USER_CODE_CHARSET
    assert "O" not in USER_CODE_CHARSET
    assert "U" not in USER_CODE_CHARSET
    assert "Y" not in USER_CODE_CHARSET
    assert "0" not in USER_CODE_CHARSET
    assert "1" not in USER_CODE_CHARSET


def test_user_code_length_and_charset() -> None:
    code = _generate_user_code(8)
    assert len(code) == 8
    assert all(c in USER_CODE_CHARSET for c in code)


def test_device_code_length_and_charset() -> None:
    code = _generate_device_code(40)
    assert len(code) == 40
    assert all(c in DEVICE_CODE_CHARSET for c in code)
