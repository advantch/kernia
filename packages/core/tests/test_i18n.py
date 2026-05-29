"""Unit tests for better_auth.i18n."""

from __future__ import annotations

from dataclasses import dataclass

import pytest
from better_auth.i18n import i18n, parse_accept_language


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        ("en", ["en"]),
        ("en-US", ["en"]),
        ("fr-FR,fr;q=0.9,en;q=0.8", ["fr", "fr", "en"]),
        ("de;q=0.5,en;q=0.8", ["en", "de"]),
        ("", []),
        (None, []),
    ],
)
def test_parse_accept_language(header: str | None, expected: list[str]) -> None:
    assert parse_accept_language(header) == expected


def test_plugin_rejects_empty_translations() -> None:
    with pytest.raises(ValueError):
        i18n(translations={})


def test_plugin_picks_en_default_when_not_specified() -> None:
    p = i18n(translations={"en": {"X": "x"}, "fr": {"X": "x-fr"}})
    assert p.default_locale == "en"


def test_plugin_picks_first_when_no_en() -> None:
    p = i18n(translations={"de": {"X": "x-de"}, "fr": {"X": "x-fr"}})
    assert p.default_locale in {"de", "fr"}


def test_plugin_translates_via_header() -> None:
    p = i18n(
        translations={
            "en": {"USER_NOT_FOUND": "User not found"},
            "fr": {"USER_NOT_FOUND": "Utilisateur non trouvé"},
        },
        detection=("header",),
    )

    @dataclass
    class _Req:
        headers: dict[str, str]
        cookies: dict[str, str]

    @dataclass
    class _Ctx:
        request: _Req
        user: object = None

    req = _Req(headers={"accept-language": "fr-FR,fr;q=0.9"}, cookies={})
    result = {"code": "USER_NOT_FOUND", "message": "User not found"}
    import asyncio

    asyncio.run(p.on_response(_Ctx(request=req), result))
    assert result["message"] == "Utilisateur non trouvé"


def test_plugin_falls_back_to_default_when_locale_unknown() -> None:
    p = i18n(translations={"en": {"X": "the-x"}, "de": {"X": "der-x"}})

    @dataclass
    class _Req:
        headers: dict[str, str]
        cookies: dict[str, str]

    @dataclass
    class _Ctx:
        request: _Req
        user: object = None

    req = _Req(headers={"accept-language": "ja-JP"}, cookies={})
    result = {"code": "X", "message": "original"}
    import asyncio

    asyncio.run(p.on_response(_Ctx(request=req), result))
    assert result["message"] == "the-x"


def test_plugin_via_cookie() -> None:
    p = i18n(
        translations={"en": {"X": "x"}, "fr": {"X": "ix"}},
        detection=("cookie",),
        locale_cookie="lang",
    )

    @dataclass
    class _Req:
        headers: dict[str, str]
        cookies: dict[str, str]

    @dataclass
    class _Ctx:
        request: _Req
        user: object = None

    req = _Req(headers={}, cookies={"lang": "fr"})
    result = {"code": "X", "message": "original"}
    import asyncio

    asyncio.run(p.on_response(_Ctx(request=req), result))
    assert result["message"] == "ix"


def test_plugin_ignores_non_dict_results() -> None:
    p = i18n(translations={"en": {"X": "x"}})
    import asyncio

    asyncio.run(p.on_response(object(), "string result"))  # type: ignore[arg-type]
    asyncio.run(p.on_response(object(), [1, 2, 3]))  # type: ignore[arg-type]
