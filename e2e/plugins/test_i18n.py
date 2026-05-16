"""End-to-end tests for the i18n plugin."""

from __future__ import annotations

import pytest

from better_auth.auth import init
from better_auth.i18n import i18n
from better_auth.plugins import email_and_password
from better_auth.types.init_options import BetterAuthOptions
from better_auth_memory_adapter import memory_adapter
from better_auth_test_utils import ASGIDriver


TRANSLATIONS = {
    "en": {
        "EMAIL_ALREADY_IN_USE": "An account with that email already exists.",
    },
    "fr": {
        "EMAIL_ALREADY_IN_USE": "Un compte avec cet email existe déjà.",
    },
    "de": {
        "EMAIL_ALREADY_IN_USE": "Ein Konto mit dieser E-Mail existiert bereits.",
    },
}


def _driver(detection: tuple[str, ...] = ("header",)) -> ASGIDriver:
    auth = init(
        BetterAuthOptions(
            database=memory_adapter(),
            secret="x" * 32,
            plugins=[
                email_and_password(),
                i18n(translations=TRANSLATIONS, default_locale="en", detection=detection),
            ],
        )
    )
    return ASGIDriver(app=auth.router.mount())


async def _trigger_duplicate_signup(d: ASGIDriver, *, headers=None) -> dict:
    payload = {"email": "u@example.com", "password": "correcthorse"}
    r1 = await d.request("POST", "/sign-up/email", json_body=payload)
    assert r1.status == 200, r1.body
    # Drop the session cookie so the second request isn't authenticated as the
    # newly created user — sign-up may auto-sign-in.
    d.cookies.clear()
    r2 = await d.request("POST", "/sign-up/email", json_body=payload, headers=headers)
    assert r2.status >= 400, r2.body
    return r2.json()


async def test_header_detection_translates_message() -> None:
    d = _driver(detection=("header",))
    body = await _trigger_duplicate_signup(
        d, headers={"accept-language": "fr-FR,fr;q=0.9"}
    )
    assert body["code"] == "EMAIL_ALREADY_IN_USE"
    assert body["message"] == TRANSLATIONS["fr"]["EMAIL_ALREADY_IN_USE"]


async def test_cookie_detection_translates_message() -> None:
    d = _driver(detection=("cookie",))
    # First sign-up succeeds. We then clear all cookies, re-inject only the
    # locale cookie, and trigger a duplicate sign-up.
    r1 = await d.request(
        "POST",
        "/sign-up/email",
        json_body={"email": "u@example.com", "password": "correcthorse"},
    )
    assert r1.status == 200, r1.body
    d.cookies.clear()
    d.cookies["locale"] = "de"
    r2 = await d.request(
        "POST",
        "/sign-up/email",
        json_body={"email": "u@example.com", "password": "correcthorse"},
    )
    body = r2.json()
    assert body["code"] == "EMAIL_ALREADY_IN_USE"
    assert body["message"] == TRANSLATIONS["de"]["EMAIL_ALREADY_IN_USE"]


async def test_missing_locale_falls_back_to_default() -> None:
    d = _driver(detection=("header",))
    body = await _trigger_duplicate_signup(
        d, headers={"accept-language": "ja-JP"}
    )
    assert body["code"] == "EMAIL_ALREADY_IN_USE"
    # default_locale="en" → English fallback.
    assert body["message"] == TRANSLATIONS["en"]["EMAIL_ALREADY_IN_USE"]
