"""Unit tests for the last-login-method resolver."""

from __future__ import annotations

from kernia.plugins.last_login_method.plugin import (
    DEFAULT_COOKIE_NAME,
    DEFAULT_MAX_AGE,
    LastLoginMethodOptions,
    _resolve_method,
    last_login_method,
)


def test_defaults() -> None:
    opts = LastLoginMethodOptions()
    assert opts.cookie_name == DEFAULT_COOKIE_NAME
    assert opts.max_age == DEFAULT_MAX_AGE


def test_resolver_known_paths() -> None:
    assert _resolve_method("/sign-in/email") == "email"
    assert _resolve_method("/sign-up/email") == "email"
    assert _resolve_method("/callback/google") == "google"
    assert _resolve_method("/oauth2/callback/github") == "github"
    assert _resolve_method("/siwe/verify") == "siwe"
    assert _resolve_method("/magic-link/verify") == "magic-link"


def test_resolver_unknown_paths() -> None:
    assert _resolve_method("/random") is None
    assert _resolve_method("") is None


def test_plugin_constructor_uses_overrides() -> None:
    plugin = last_login_method(cookie_name="x", max_age=42)
    assert plugin.id == "last-login-method"
