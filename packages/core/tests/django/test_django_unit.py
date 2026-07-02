"""Unit tests for the Django request → ASGI scope translator."""

from __future__ import annotations

import pytest

pytest.importorskip("django")

import django
from django.conf import settings


def _ensure_django() -> None:
    if not settings.configured:
        settings.configure(
            DEBUG=True,
            SECRET_KEY="test-secret",
            DATABASES={
                "default": {
                    "ENGINE": "django.db.backends.sqlite3",
                    "NAME": ":memory:",
                }
            },
            INSTALLED_APPS=["kernia_django"],
            MIDDLEWARE=[],
            ROOT_URLCONF=None,
            ALLOWED_HOSTS=["*"],
            USE_TZ=True,
        )
        django.setup()


_ensure_django()

from django.test import RequestFactory  # noqa: E402
from kernia_django.views import django_request_to_scope  # noqa: E402


def test_translator_basic_get() -> None:
    rf = RequestFactory()
    req = rf.get(
        "/api/auth/get-session?foo=bar",
        HTTP_COOKIE="better-auth.session_token=abc",
        HTTP_X_CUSTOM="yes",
    )
    scope = django_request_to_scope(req)
    assert scope["type"] == "http"
    assert scope["method"] == "GET"
    assert scope["path"] == "/api/auth/get-session"
    assert scope["query_string"] == b"foo=bar"
    headers = dict(scope["headers"])
    assert headers[b"cookie"] == b"better-auth.session_token=abc"
    assert headers[b"x-custom"] == b"yes"


def test_translator_strips_base_path() -> None:
    rf = RequestFactory()
    req = rf.get("/api/auth/sign-in/email")
    scope = django_request_to_scope(req, base_path="/api/auth")
    assert scope["path"] == "/sign-in/email"


def test_translator_post_includes_content_type() -> None:
    rf = RequestFactory()
    req = rf.post(
        "/api/auth/sign-up/email",
        data='{"email":"x@y.com"}',
        content_type="application/json",
    )
    scope = django_request_to_scope(req, base_path="/api/auth")
    assert scope["method"] == "POST"
    assert scope["path"] == "/sign-up/email"
    headers = dict(scope["headers"])
    assert headers[b"content-type"] == b"application/json"


def test_translator_root_path_becomes_slash() -> None:
    rf = RequestFactory()
    req = rf.get("/api/auth")
    scope = django_request_to_scope(req, base_path="/api/auth")
    assert scope["path"] == "/"


def test_translator_non_matching_base_path_unchanged() -> None:
    rf = RequestFactory()
    req = rf.get("/elsewhere")
    scope = django_request_to_scope(req, base_path="/api/auth")
    assert scope["path"] == "/elsewhere"
