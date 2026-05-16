"""Pure-function tests for the phone-number plugin."""

from __future__ import annotations

import pytest

from better_auth.plugins.phone_number import (
    PHONE_NUMBER_ERROR_CODES,
    PHONE_NUMBER_USER_FIELDS,
    generate_otp,
    phone_number,
    phone_number_schema,
)


def test_otp_default_is_six_digits() -> None:
    otp = generate_otp()
    assert len(otp) == 6 and otp.isdigit()


def test_otp_custom_length_padding() -> None:
    # Padding always pads with leading zeros for short random values.
    samples = {generate_otp(4) for _ in range(50)}
    assert all(len(s) == 4 and s.isdigit() for s in samples)


def test_plugin_id_and_endpoints() -> None:
    p = phone_number()
    assert p.id == "phone-number"
    paths = {ep.path for ep in p.endpoints}  # type: ignore[union-attr]
    assert paths == {
        "/sign-in/phone-number",
        "/phone-number/send-otp",
        "/phone-number/verify",
        "/phone-number/request-password-reset",
        "/phone-number/reset-password",
    }


def test_schema_extends_user_table() -> None:
    s = phone_number_schema()
    assert "user" in s.extend
    field_names = {f.name for f in s.extend["user"]}
    assert field_names == {"phoneNumber", "phoneNumberVerified"}
    phone_field = next(f for f in PHONE_NUMBER_USER_FIELDS if f.name == "phoneNumber")
    assert phone_field.unique is True
    assert phone_field.required is False


def test_error_codes_cover_failure_modes() -> None:
    for code in (
        "INVALID_PHONE_NUMBER_OR_PASSWORD",
        "PHONE_NUMBER_NOT_CONFIGURED",
        "PHONE_NUMBER_SIGN_UP_DISABLED",
    ):
        assert code in PHONE_NUMBER_ERROR_CODES


def test_zero_otp_length_rejected() -> None:
    with pytest.raises(ValueError):
        generate_otp(0)
