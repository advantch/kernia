"""Pure-function tests for the email-OTP plugin."""

from __future__ import annotations

import pytest
from kernia.plugins.email_otp import EMAIL_OTP_ERROR_CODES, email_otp, generate_otp
from kernia.plugins.email_otp.routes import _identifier


def test_default_otp_is_six_digits() -> None:
    for _ in range(50):
        otp = generate_otp()
        assert len(otp) == 6
        assert otp.isdigit()


def test_custom_length() -> None:
    otp = generate_otp(8)
    assert len(otp) == 8
    assert otp.isdigit()


def test_zero_length_rejected() -> None:
    with pytest.raises(ValueError):
        generate_otp(0)


def test_identifier_lowercases_email() -> None:
    assert _identifier("sign-in", "Alice@Example.com") == "email-otp:sign-in:alice@example.com"


def test_plugin_id_and_paths() -> None:
    p = email_otp()
    assert p.id == "email-otp"
    paths = {ep.path for ep in p.endpoints}  # type: ignore[union-attr]
    assert paths == {
        "/sign-in/email-otp",
        "/email-otp/verify",
        "/email-otp/send-verification-otp",
        "/email-otp/verify-email",
        "/forget-password/email-otp",
        "/email-otp/request-password-reset",
        "/email-otp/reset-password",
        "/email-otp/create-verification-otp",
        "/email-otp/get-verification-otp",
        "/email-otp/check-verification-otp",
        "/email-otp/request-email-change",
        "/email-otp/change-email",
    }


def test_error_codes_include_required_failures() -> None:
    for code in ("OTP_EXPIRED", "INVALID_OTP", "TOO_MANY_ATTEMPTS"):
        assert code in EMAIL_OTP_ERROR_CODES
