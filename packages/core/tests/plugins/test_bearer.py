"""Unit tests for the bearer plugin (signature verification only)."""

from __future__ import annotations

from kernia.cookies import sign
from kernia.plugins.bearer.plugin import BearerOptions, _make_on_request


def test_bearer_options_default_requires_signature() -> None:
    # Upstream parity: `requireSignature` defaults to false.
    opts = BearerOptions()
    assert opts.require_signature is False


def test_bearer_signed_token_format_is_compatible_with_cookie() -> None:
    # The bearer plugin verifies the same HMAC as `cookies.verify`, so a value
    # produced by `sign()` is a valid bearer token.
    signed = sign("session-tok", secret="s3cret")
    assert signed.startswith("session-tok.")
    # The on_request hook is async — we only verify the factory returns a callable.
    hook = _make_on_request(BearerOptions())
    assert callable(hook)
