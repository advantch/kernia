"""Django app config for kernia-django.

Importing this module triggers no Django machinery; the config is only loaded
once the user adds ``kernia_django`` to ``INSTALLED_APPS``.
"""

from __future__ import annotations

from django.apps import AppConfig


class KerniaConfig(AppConfig):
    """Standard Django app config — no ready-hook side effects.

    The auth instance lives on whatever the user passes into ``setup()`` /
    ``KerniaView.as_view(auth=...)``. We deliberately don't read it from
    settings here so users can construct the ``Kernia`` object at module
    load time without forcing a Django settings dependency on the core.
    """

    name = "kernia_django"
    label = "kernia_django"
    verbose_name = "Better Auth"
    default_auto_field = "django.db.models.BigAutoField"
