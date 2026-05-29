"""Unit tests for the device-authorization code generators."""

from __future__ import annotations

import re

from better_auth.plugins.device_authorization.routes import (
    DEFAULT_USER_CODE_CHARSET,
    DEVICE_CODE_CHARSET,
    _default_generate_device_code,
    _default_generate_user_code,
)


def test_user_code_charset_matches_upstream() -> None:
    # Upstream charset: "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" — all [A-Z0-9], with the
    # visually ambiguous 0/1/O/I removed.
    assert DEFAULT_USER_CODE_CHARSET == "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    assert re.fullmatch(r"[A-Z0-9]+", DEFAULT_USER_CODE_CHARSET)
    for ambiguous in ("0", "1", "O", "I"):
        assert ambiguous not in DEFAULT_USER_CODE_CHARSET


def test_user_code_length_and_charset() -> None:
    code = _default_generate_user_code(8)
    assert len(code) == 8
    assert all(c in DEFAULT_USER_CODE_CHARSET for c in code)
    # Matches the upstream user_code shape /^[A-Z0-9]{8}$/.
    assert re.fullmatch(r"[A-Z0-9]{8}", code)


def test_device_code_length_and_charset() -> None:
    code = _default_generate_device_code(40)
    assert len(code) == 40
    assert all(c in DEVICE_CODE_CHARSET for c in code)
