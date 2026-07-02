"""Django integration for Kernia.

Public surface:

* :class:`apps.KerniaConfig` — Django app config (add to ``INSTALLED_APPS``).
* :class:`middleware.KerniaMiddleware` — populates
  ``request.kernia_session`` / ``request.kernia_user``.
* :func:`decorators.require_session` — 401-JSON view decorator.
* :class:`views.KerniaView` — class-based view that forwards to the
  Kernia ASGI router.
* :func:`setup` — convenience that returns urlpatterns for the auth router.

Django is sync-by-default; the bridge uses ``asgiref.sync.async_to_sync`` to
call the async core. Each Kernia request pays one thread hop.
"""

from kernia_django.decorators import require_session
from kernia_django.middleware import KerniaMiddleware
from kernia_django.views import KerniaView, setup

default_app_config = "kernia_django.apps.KerniaConfig"

__all__ = [
    "KerniaMiddleware",
    "KerniaView",
    "default_app_config",
    "require_session",
    "setup",
]
