"""Unit tests for the last-login-method resolver."""

from __future__ import annotations

from kernia.plugins.last_login_method.plugin import (
    DEFAULT_COOKIE_NAME,
    DEFAULT_MAX_AGE,
    LastLoginMethodOptions,
    _default_resolve_method,
    last_login_method,
)


def _ctx(path: str, **path_params: str) -> SimpleNamespace:
    """Build the minimal context the resolver reads (request.path + path_params)."""
    return SimpleNamespace(
        request=SimpleNamespace(path=path),
        path_params=dict(path_params),
    )


def test_defaults() -> None:
    opts = LastLoginMethodOptions()
    assert opts.cookie_name == DEFAULT_COOKIE_NAME
    assert opts.max_age == DEFAULT_MAX_AGE


def test_resolver_known_paths() -> None:
    assert _default_resolve_method(_ctx("/sign-in/email")) == "email"
    assert _default_resolve_method(_ctx("/sign-up/email")) == "email"
    assert _default_resolve_method(_ctx("/callback/google", id="google")) == "google"
    assert (
        _default_resolve_method(_ctx("/oauth2/callback/github", providerId="github"))
        == "github"
    )
    assert _default_resolve_method(_ctx("/siwe/verify")) == "siwe"
    assert _default_resolve_method(_ctx("/magic-link/verify")) == "magic-link"


def test_resolver_unknown_paths() -> None:
    assert _default_resolve_method(_ctx("/random")) is None
    assert _default_resolve_method(_ctx("")) is None


def test_plugin_constructor_uses_overrides() -> None:
    plugin = last_login_method(cookie_name="x", max_age=42)
    assert plugin.id == "last-login-method"
