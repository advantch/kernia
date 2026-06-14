"""Unit tests for the two-factor plugin: schema + TOTP correctness."""

from __future__ import annotations

import time

import pyotp
from kernia.plugins.two_factor import TWO_FACTOR_ERROR_CODES, two_factor


def test_two_factor_plugin_id_and_endpoints() -> None:
    p = two_factor()
    assert p.id == "two-factor"
    paths = {ep.path for ep in (p.endpoints or ())}
    expected = {
        "/two-factor/enable",
        "/two-factor/verify-totp",
        "/two-factor/disable",
        "/two-factor/generate-backup-codes",
        "/two-factor/verify-backup-code",
    }
    assert expected <= paths


def test_two_factor_schema_contributes_two_tables_and_user_columns() -> None:
    p = two_factor()
    assert p.schema is not None
    table_names = {m.name for m in p.schema.tables}
    assert {"twoFactorConfirmation", "twoFactorBackupCode"} <= table_names
    user_extras = {f.name for f in p.schema.extend.get("user", ())}
    assert {"twoFactorEnabled", "twoFactorSecret"} <= user_extras


def test_two_factor_error_codes_documented() -> None:
    assert "INVALID_TWO_FACTOR_CODE" in TWO_FACTOR_ERROR_CODES
    assert "INVALID_BACKUP_CODE" in TWO_FACTOR_ERROR_CODES


def test_pyotp_round_trip_happy_path() -> None:
    """Lock in the TOTP library invariant the plugin relies on:
    `TOTP(secret).now()` produces a code that verifies with the same secret."""
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    code = totp.now()
    assert totp.verify(code, valid_window=0)


def test_pyotp_old_code_rejected_with_no_window() -> None:
    """Replay protection: codes from 5 min ago do not verify when
    valid_window=0 (the plugin's default)."""
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    old_code = totp.at(int(time.time()) - 600)
    # 600s is 20 steps; valid_window=0 only accepts the current step.
    assert not totp.verify(old_code, valid_window=0)
