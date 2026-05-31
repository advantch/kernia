"""Pure-function tests for the magic-link plugin."""

from __future__ import annotations

from kernia.plugins.magic_link import MAGIC_LINK_ERROR_CODES, magic_link
from kernia.plugins.magic_link.routes import (
    MagicLinkVerifyQuery,
    SignInMagicLinkBody,
)


def test_plugin_id_and_endpoints() -> None:
    p = magic_link()
    assert p.id == "magic-link"
    paths = {ep.path for ep in p.endpoints}  # type: ignore[union-attr]
    assert paths == {"/sign-in/magic-link", "/magic-link/verify"}


def test_error_codes_cover_failure_modes() -> None:
    for code in (
        "MAGIC_LINK_INVALID",
        "MAGIC_LINK_EXPIRED",
        "MAGIC_LINK_SIGN_UP_DISABLED",
        "MAGIC_LINK_NOT_CONFIGURED",
    ):
        assert code in MAGIC_LINK_ERROR_CODES


def test_body_alias_camelcase() -> None:
    body = SignInMagicLinkBody.model_validate({
        "email": "a@b.com",
        "callbackURL": "/done",
    })
    assert body.email == "a@b.com"
    assert body.callback_url == "/done"


def test_query_default_callback_is_none() -> None:
    q = MagicLinkVerifyQuery.model_validate({"token": "abc"})
    assert q.token == "abc"
    assert q.callback_url is None


def test_schema_is_none() -> None:
    """Magic link reuses the core verification table only."""
    p = magic_link()
    assert p.schema is None
