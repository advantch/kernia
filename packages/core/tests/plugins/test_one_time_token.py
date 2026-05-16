"""Pure-function tests for the one-time-token plugin."""

from __future__ import annotations

from better_auth.plugins.one_time_token import ONE_TIME_TOKEN_ERROR_CODES, one_time_token
from better_auth.plugins.one_time_token.routes import (
    GenerateOneTimeTokenBody,
    VerifyOneTimeTokenBody,
)


def test_plugin_id_and_paths() -> None:
    p = one_time_token()
    assert p.id == "one-time-token"
    paths = {ep.path for ep in p.endpoints}  # type: ignore[union-attr]
    assert paths == {"/generate-one-time-token", "/verify-one-time-token"}


def test_generate_requires_session() -> None:
    p = one_time_token()
    by_path = {ep.path: ep for ep in p.endpoints}  # type: ignore[union-attr]
    assert by_path["/generate-one-time-token"].options.requires_session is True
    assert by_path["/verify-one-time-token"].options.requires_session is False


def test_body_defaults() -> None:
    g = GenerateOneTimeTokenBody.model_validate({})
    assert g.purpose == "default"
    assert g.expires_in is None
    v = VerifyOneTimeTokenBody.model_validate({"token": "abc"})
    assert v.token == "abc"


def test_error_codes() -> None:
    assert "ONE_TIME_TOKEN_INVALID" in ONE_TIME_TOKEN_ERROR_CODES
    assert "ONE_TIME_TOKEN_EXPIRED" in ONE_TIME_TOKEN_ERROR_CODES
