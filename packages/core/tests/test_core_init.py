"""Smoke: building a `BetterAuth` handle from options + plugins works end-to-end.

Exercises every Phase-1 contract: BetterAuthOptions, plugin registration, endpoint
ownership stamping, the error registry, and cookie signing.
"""

from __future__ import annotations

import pytest

from better_auth.auth import init
from better_auth.cookies import new_token, render_set_cookie, sign, verify
from better_auth.plugins import email_and_password
from better_auth.types.cookie import CookieAttributes
from better_auth.types.init_options import BetterAuthOptions
from better_auth_memory_adapter import memory_adapter


def test_init_with_email_password_plugin_registers_routes() -> None:
    options = BetterAuthOptions(
        database=memory_adapter(),
        secret="test-secret",
        plugins=[email_and_password()],
    )
    auth = init(options)

    # Every email/password route is registered with owner attribution.
    assert auth.router.lookup("POST", "/sign-up/email") is not None
    assert auth.router.lookup("POST", "/sign-in/email") is not None
    assert auth.router.lookup("POST", "/forget-password") is not None
    assert auth.router.lookup("POST", "/reset-password") is not None

    sign_in = auth.router.lookup("POST", "/sign-in/email")
    assert sign_in is not None
    # `lookup` returns `(endpoint, path_params)` since dynamic routes landed.
    sign_in_ep = sign_in[0] if isinstance(sign_in, tuple) else sign_in
    assert sign_in_ep.owner == "email-password"

    # Error codes from the plugin are merged into the registry.
    assert "INVALID_CREDENTIALS" in auth.errors.codes
    # Core codes are still present.
    assert "UNAUTHORIZED" in auth.errors.codes


def test_init_rejects_missing_secret() -> None:
    with pytest.raises(ValueError, match="secret is required"):
        init(BetterAuthOptions(database=memory_adapter(), secret=""))


def test_init_detects_endpoint_collisions() -> None:
    # Registering the same plugin twice triggers the collision check.
    options = BetterAuthOptions(
        database=memory_adapter(),
        secret="s",
        plugins=[email_and_password(), email_and_password()],
    )
    with pytest.raises(ValueError, match="Endpoint collision"):
        init(options)


def test_cookie_sign_round_trip() -> None:
    token = new_token()
    signed = sign(token, secret="s3cret")
    assert verify(signed, secret="s3cret") == token
    assert verify(signed, secret="wrong") is None
    # Tampered value is rejected.
    tampered = signed.replace(token[0], "Z" if token[0] != "Z" else "Y", 1)
    if tampered != signed:
        assert verify(tampered, secret="s3cret") is None


def test_render_set_cookie_includes_attributes() -> None:
    header = render_set_cookie(
        "better-auth.session_token",
        "tok",
        CookieAttributes(
            path="/",
            max_age=3600,
            http_only=True,
            secure=True,
            same_site="lax",
        ),
    )
    assert "better-auth.session_token=tok" in header
    assert "Path=/" in header
    assert "Max-Age=3600" in header
    assert "HttpOnly" in header
    assert "Secure" in header
    assert "SameSite=Lax" in header
