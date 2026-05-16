"""Django integration for better-auth.

Public surface:

* :class:`apps.BetterAuthConfig` — Django app config (add to ``INSTALLED_APPS``).
* :class:`middleware.BetterAuthMiddleware` — populates
  ``request.better_auth_session`` / ``request.better_auth_user``.
* :func:`decorators.require_session` — 401-JSON view decorator.
* :class:`views.BetterAuthView` — class-based view that forwards to the
  better-auth ASGI router.
* :func:`setup` — convenience that returns urlpatterns for the auth router.

Django is sync-by-default; the bridge uses ``asgiref.sync.async_to_sync`` to
call the async core. Each better-auth request pays one thread hop.
"""

from better_auth_django.decorators import require_session
from better_auth_django.middleware import BetterAuthMiddleware
from better_auth_django.views import BetterAuthView, setup

default_app_config = "better_auth_django.apps.BetterAuthConfig"

__all__ = [
    "BetterAuthMiddleware",
    "BetterAuthView",
    "default_app_config",
    "require_session",
    "setup",
]
