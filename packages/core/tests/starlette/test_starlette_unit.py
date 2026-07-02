"""Unit tests for the shared URL-strip semantics used by the Starlette mount."""

from __future__ import annotations

from kernia.integrations.session import strip_base_path


def test_strip_base_path_trims_prefix() -> None:
    scope = {"type": "http", "path": "/api/auth/sign-in/email"}
    out = strip_base_path(scope, "/api/auth")
    assert out["path"] == "/sign-in/email"
    # Original is not mutated.
    assert scope["path"] == "/api/auth/sign-in/email"


def test_strip_base_path_root_becomes_slash() -> None:
    scope = {"type": "http", "path": "/api/auth"}
    out = strip_base_path(scope, "/api/auth")
    assert out["path"] == "/"


def test_strip_base_path_no_match_returns_unchanged() -> None:
    scope = {"type": "http", "path": "/other"}
    out = strip_base_path(scope, "/api/auth")
    # Same identity — no copy when nothing to strip.
    assert out is scope


def test_strip_base_path_non_http_is_passthrough() -> None:
    scope = {"type": "lifespan"}
    out = strip_base_path(scope, "/api/auth")
    assert out is scope


def test_strip_base_path_empty_prefix_is_noop() -> None:
    scope = {"type": "http", "path": "/x"}
    out = strip_base_path(scope, "")
    assert out is scope
