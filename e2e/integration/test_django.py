"""Django integration end-to-end.

Bootstraps a minimal Django settings module in-process, wires the middleware
and the auth router into a urlconf, and exercises sign-up / protected view /
sign-out via :class:`django.test.Client`.
"""

from __future__ import annotations

import sys
import types

import pytest

pytest.importorskip("django")


@pytest.fixture
def django_setup():
    import django
    from better_auth.auth import init
    from better_auth.plugins.email_password import email_and_password
    from better_auth.types.init_options import BetterAuthOptions
    from better_auth_django import (
        require_session,
    )
    from better_auth_django import setup as ba_setup
    from better_auth_memory_adapter import memory_adapter
    from django.conf import settings
    from django.http import JsonResponse
    from django.urls import path

    auth = init(
        BetterAuthOptions(
            database=memory_adapter(),
            secret="test-secret",
            plugins=[email_and_password()],
        )
    )

    @require_session
    def me(request):  # type: ignore[no-untyped-def]
        return JsonResponse({"user_id": request.better_auth_session.user_id})

    def maybe_me(request):  # type: ignore[no-untyped-def]
        sess = getattr(request, "better_auth_session", None)
        return JsonResponse({"signed_in": sess is not None})

    urlpatterns = [
        path("me", me),
        path("maybe-me", maybe_me),
        *ba_setup(auth, url_prefix="/api/auth"),
    ]

    # Synthesize a urlconf module for Django.
    urlconf_name = "better_auth_django_test_urls"
    mod = types.ModuleType(urlconf_name)
    mod.urlpatterns = urlpatterns  # type: ignore[attr-defined]
    sys.modules[urlconf_name] = mod

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
            INSTALLED_APPS=["better_auth_django"],
            MIDDLEWARE=["better_auth_django.middleware.BetterAuthMiddleware"],
            ROOT_URLCONF=urlconf_name,
            ALLOWED_HOSTS=["*"],
            USE_TZ=True,
            BETTER_AUTH=auth,
        )
        django.setup()
    else:
        settings.BETTER_AUTH = auth
        settings.ROOT_URLCONF = urlconf_name
        settings.MIDDLEWARE = ["better_auth_django.middleware.BetterAuthMiddleware"]
        # Reuse the existing urlconf module (already in sys.modules) but
        # rebind its urlpatterns so it points at the freshly-built auth.
        existing = sys.modules[urlconf_name]
        existing.urlpatterns = urlpatterns  # type: ignore[attr-defined]
        from django.urls import clear_url_caches

        clear_url_caches()

    from django.test import Client

    return auth, Client()


def test_signup_protected_signout_flow(django_setup) -> None:
    _, client = django_setup
    r = client.post(
        "/api/auth/sign-up/email",
        data='{"email":"x@example.com","password":"correcthorse"}',
        content_type="application/json",
    )
    assert r.status_code == 200, r.content
    # Cookie should have been forwarded onto the test client jar.
    assert "better-auth.session_token" in client.cookies

    r = client.get("/maybe-me")
    assert r.json() == {"signed_in": True}

    r = client.get("/me")
    assert r.status_code == 200
    assert "user_id" in r.json()

    r = client.post("/api/auth/sign-out")
    assert r.status_code == 200

    r = client.get("/me")
    assert r.status_code == 401


def test_require_session_blocks_unauthenticated(django_setup) -> None:
    _, client = django_setup
    client.cookies.clear()
    r = client.get("/me")
    assert r.status_code == 401
    assert r.json() == {"error": "UNAUTHORIZED"}
