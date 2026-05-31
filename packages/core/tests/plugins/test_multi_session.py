"""Unit tests for the multi-session list cookie encoding."""

from __future__ import annotations

from kernia.cookies import sign, verify
from kernia.plugins.multi_session.routes import (
    SESSION_LIST_COOKIE,
    _decode_list,
    _encode_list,
)


def test_encode_decode_round_trip() -> None:
    records = [
        {"id": "a", "token": "tok-a"},
        {"id": "b", "token": "tok-b"},
    ]
    encoded = _encode_list(records)
    assert _decode_list(encoded) == records


def test_decode_handles_garbage() -> None:
    assert _decode_list("not-base64!@#") == []
    assert _decode_list("") == []


def test_decode_strips_unexpected_shapes() -> None:
    encoded = _encode_list([{"id": "ok", "token": "t"}, {"junk": "yes"}])  # type: ignore[list-item]
    assert _decode_list(encoded) == [{"id": "ok", "token": "t"}]


def test_signed_list_cookie_round_trip() -> None:
    records = [{"id": "x", "token": "y"}]
    encoded = _encode_list(records)
    signed = sign(encoded, secret="s")
    assert verify(signed, secret="s") == encoded
    assert _decode_list(verify(signed, secret="s")) == records
    assert SESSION_LIST_COOKIE == "better-auth.session_list"
