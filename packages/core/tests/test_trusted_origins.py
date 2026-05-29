"""Unit tests for better_auth.auth.trusted_origins."""

from __future__ import annotations

import pytest
from better_auth.auth.trusted_origins import is_state_changing, is_trusted, normalize_origin


@pytest.mark.parametrize(
    ("inp", "out"),
    [
        ("https://example.com", "https://example.com"),
        ("https://example.com/path", "https://example.com"),
        ("https://example.com:8443/path?q=1", "https://example.com:8443"),
        ("http://localhost:3000", "http://localhost:3000"),
        ("example.com", "https://example.com"),
        ("", None),
        ("not a url", None),
    ],
)
def test_normalize_origin(inp: str, out: str | None) -> None:
    assert normalize_origin(inp) == out


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE", "post"])
def test_is_state_changing_true(method: str) -> None:
    assert is_state_changing(method)


@pytest.mark.parametrize("method", ["GET", "HEAD", "OPTIONS"])
def test_is_state_changing_false(method: str) -> None:
    assert not is_state_changing(method)


def test_same_origin_accepted() -> None:
    assert is_trusted(
        origin="https://app.example.com",
        referer=None,
        base_url="https://app.example.com",
        trusted_origins=(),
    )


def test_no_origin_no_referer_accepted_for_ssr() -> None:
    assert is_trusted(origin=None, referer=None, base_url="https://app.example.com", trusted_origins=())


def test_cross_origin_rejected() -> None:
    assert not is_trusted(
        origin="https://evil.example.com",
        referer=None,
        base_url="https://app.example.com",
        trusted_origins=(),
    )


def test_trusted_origins_list_accepted() -> None:
    assert is_trusted(
        origin="https://mobile.example.com",
        referer=None,
        base_url="https://app.example.com",
        trusted_origins=("https://mobile.example.com",),
    )


def test_referer_falls_back_when_origin_missing() -> None:
    assert is_trusted(
        origin=None,
        referer="https://app.example.com/login",
        base_url="https://app.example.com",
        trusted_origins=(),
    )


def test_bad_origin_format_rejected() -> None:
    assert not is_trusted(
        origin="not a url",
        referer=None,
        base_url="https://app.example.com",
        trusted_origins=(),
    )
