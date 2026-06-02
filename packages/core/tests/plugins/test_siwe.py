"""Unit tests for the SIWE plugin: schema + error codes + nonce parser."""

from __future__ import annotations

from kernia.plugins.siwe import SIWE_ERROR_CODES, siwe
from kernia.plugins.siwe.routes import _extract_nonce


def test_siwe_plugin_id_and_endpoints() -> None:
    p = siwe()
    assert p.id == "siwe"
    paths = {ep.path for ep in (p.endpoints or ())}
    assert {"/siwe/nonce", "/siwe/verify"} <= paths


def test_siwe_extends_user_schema_with_wallet_address() -> None:
    p = siwe()
    assert p.schema is not None
    user_extras = p.schema.extend.get("user", ())
    field_map = {f.name: f for f in user_extras}
    assert "walletAddress" in field_map
    assert field_map["walletAddress"].unique is True


def test_siwe_error_codes_documented() -> None:
    assert "UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE" in SIWE_ERROR_CODES
    assert "INVALID_SIWE_SIGNATURE" in SIWE_ERROR_CODES


def test_extract_nonce_parses_eip4361_message() -> None:
    msg = (
        "example.com wants you to sign in with your Ethereum account:\n"
        "0xabc\n\nSignin\n\nURI: https://example.com\nVersion: 1\nChain ID: 1\n"
        "Nonce: abc123XYZ\nIssued At: 2026-01-01T00:00:00Z\n"
    )
    assert _extract_nonce(msg) == "abc123XYZ"


def test_extract_nonce_missing_returns_none() -> None:
    assert _extract_nonce("no nonce here") is None
